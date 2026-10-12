import { useEffect, useRef, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { ApiError } from '../api/client';
import { friendlyMessage, isCode } from '../api/errorMessages';
import { DnsHints, DnsRecordsTable, DomainStatusChip } from '../components/DnsRecordsTable';
import { DomainStateBanner } from '../components/DomainStateBanner';
import { Button, Card, Chip, ConfirmDialog, CopyButton, EmptyState, ErrorNotice, KeyValue, Loading, Notice, PageHeader } from '../components/ui';
import { formatDateTime, formatRelative } from '../lib/format';
import { useAction, useApi, useCooldown, useDocumentTitle, usePolling } from '../lib/hooks';

const VERIFY_COOLDOWN_SECONDS = 30;

export default function DomainDetail({ id }: { id?: string }) {
  const domainId = id ?? '';
  const { data: domain, error, loading, reload, setData } = useApi(() => api.domain(domainId), [domainId]);
  useDocumentTitle(domain ? domain.name : 'Domain');

  const cooldown = useCooldown();
  const [announce, setAnnounce] = useState('');
  const [verifyNote, setVerifyNote] = useState<string | null>(null);
  const [rotating, setRotating] = useState(false);
  const wasCoolingDown = useRef(false);

  // Announce only the start and the end of the cooldown for screen readers.
  useEffect(() => {
    if (cooldown.remaining > 0) wasCoolingDown.current = true;
    else if (wasCoolingDown.current) {
      wasCoolingDown.current = false;
      setAnnounce('You can verify again.');
    }
  }, [cooldown.remaining]);

  const verify = useAction(async () => {
    try {
      const d = await api.verifyDomain(domainId);
      setData(d);
      setVerifyNote(null);
      setAnnounce('Verification requested.');
      cooldown.start(VERIFY_COOLDOWN_SECONDS);
      return d;
    } catch (e) {
      if (isCode(e, 'rate_limited')) {
        cooldown.start((e as ApiError).retryAfter ?? VERIFY_COOLDOWN_SECONDS);
        setVerifyNote(friendlyMessage(e));
        setAnnounce('Verify is rate limited.');
        return undefined;
      }
      throw e;
    }
  });

  const rotate = useAction(async () => {
    const d = await api.rotateDkim(domainId);
    setData(d);
    return d;
  });

  usePolling(
    async () => {
      try {
        setData(await api.domain(domainId));
      } catch {
        /* keep showing the last state; the next tick retries */
      }
    },
    30_000,
    domain?.status === 'pending' || domain?.status === 'verifying',
  );

  if (loading && !domain) return <Loading />;
  if (isCode(error, 'not_found')) {
    return (
      <EmptyState title="Domain not found" action={<a href="/domains">Back to domains</a>}>
        <p>This domain does not exist or was deleted.</p>
      </EmptyState>
    );
  }
  if (error !== undefined && !domain) return <ErrorNotice error={error} onRetry={reload} />;
  if (!domain) return null;

  const coolingDown = cooldown.remaining > 0;

  return (
    <>
      <PageHeader
        title={domain.name}
        subtitle={
          <>
            <a href="/domains">All domains</a>
          </>
        }
        actions={
          <>
            <DomainStatusChip status={domain.status} />
            {domain.sendingPaused && <Chip tone="bad">Sending paused</Chip>}
            <Button variant="primary" onClick={() => void verify.run()} busy={verify.busy} disabled={coolingDown}>
              {coolingDown ? `Verify again in ${cooldown.remaining} s` : 'Verify now'}
            </Button>
          </>
        }
      />
      <span class="sr-only" role="status" aria-live="polite">
        {announce}
      </span>
      {verifyNote && <Notice tone="warn">{verifyNote}</Notice>}
      {verify.error !== undefined && <ErrorNotice error={verify.error} />}
      {error !== undefined && <ErrorNotice error={error} onRetry={reload} />}

      <DomainStateBanner domain={domain} />

      <Card title="Verification">
        <KeyValue
          items={[
            ['Status', <DomainStatusChip status={domain.status} />],
            ['Last checked', domain.lastCheckedAt ? `${formatDateTime(domain.lastCheckedAt)} (${formatRelative(domain.lastCheckedAt)})` : 'Not checked yet'],
            ['Next check', domain.nextCheckAt ? `${formatDateTime(domain.nextCheckAt)} (${formatRelative(domain.nextCheckAt)})` : '-'],
            ['Last error', domain.lastError ?? 'None'],
          ]}
        />
        <p class="hint">Verify now is limited to once every 30 seconds per domain. EggMail also re-checks automatically.</p>
      </Card>

      <Card title="DNS records">
        <DnsRecordsTable records={domain.records} />
      </Card>
      <DnsHints />

      <Card
        title="DKIM key"
        actions={
          <Button onClick={() => setRotating(true)}>Rotate DKIM key</Button>
        }
      >
        <KeyValue
          items={[
            ['Selector', <code>{domain.dkim.selector}</code>],
            ['Active', domain.dkim.active ? 'Yes' : 'No'],
            ['Created', formatDateTime(domain.dkim.createdAt)],
          ]}
        />
        <div class="stack">
          <span class="label">Public key (RSA-2048)</span>
          <div class="value-cell">
            <code class="dns-value" data-testid="dkim-public-key">
              {domain.dkim.publicKey}
            </code>
            <CopyButton text={domain.dkim.publicKey} what="DKIM public key" />
          </div>
        </div>
        {rotate.error !== undefined && !rotating && <ErrorNotice error={rotate.error} />}
      </Card>

      {rotating && (
        <ConfirmDialog
          title="Rotate the DKIM key?"
          confirmLabel="Rotate key"
          danger={false}
          busy={rotate.busy}
          error={rotate.error}
          onCancel={() => {
            rotate.clearError();
            setRotating(false);
          }}
          onConfirm={async () => {
            const d = await rotate.run();
            if (d) setRotating(false);
          }}
        >
          <p>
            This publishes a new selector (N+1) with a new key. The current selector stays valid for at least 7 days so mail already signed keeps verifying.
          </p>
          <p>Add the new DNS record shown in the table before mail starts to be signed with the new selector. Selector names are never reused.</p>
        </ConfirmDialog>
      )}
    </>
  );
}
