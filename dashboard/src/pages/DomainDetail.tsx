import { useEffect, useRef, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { ApiError } from '../api/client';
import { friendlyMessage, isCode } from '../api/errorMessages';
import { DnsHints, DnsRecordsTable, DomainStatusChip, ZoneFileBlock, recordProgress } from '../components/DnsRecordsTable';
import { DomainStateBanner } from '../components/DomainStateBanner';
import type { DkimKeyInfo } from '../api/types';
import { Button, Card, Chip, ConfirmDialog, CopyButton, EmptyState, ErrorNotice, KeyValue, Loading, Notice, PageHeader } from '../components/ui';
import { formatDateTime, formatRelative } from '../lib/format';
import { useAction, useApi, useCooldown, useDocumentTitle, usePolling } from '../lib/hooks';

const VERIFY_COOLDOWN_SECONDS = 30;

export default function DomainDetail({ id }: { id?: string }) {
  const domainId = id ?? '';
  const { data: domain, error, loading, reload, setData } = useApi(() => api.domain(domainId), [domainId]);
  // The text to publish (zone file, MTA-STS policy file) is loaded again whenever the domain changed: a check, a DKIM rotation.
  const recordsState = useApi(async () => (domain ? api.domainRecords(domainId) : undefined), [domainId, domain?.lastCheckedAt, domain?.dkimKeys?.length, domain?.status]);
  const publishing = recordsState.data;
  useDocumentTitle(domain ? domain.name : 'Domain');

  const cooldown = useCooldown();
  const [announce, setAnnounce] = useState('');
  const [verifyNote, setVerifyNote] = useState<string | null>(null);
  const [rotating, setRotating] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const wasCoolingDown = useRef(false);

  // Announce only the start and the end of the cooldown for screen readers.
  useEffect(() => {
    if (cooldown.remaining > 0) wasCoolingDown.current = true;
    else if (wasCoolingDown.current) {
      wasCoolingDown.current = false;
      setAnnounce('You can check again.');
    }
  }, [cooldown.remaining]);

  const verify = useAction(async () => {
    try {
      const d = await api.verifyDomain(domainId);
      setData(d);
      setVerifyNote(null);
      setAnnounce('DNS check finished.');
      cooldown.start(VERIFY_COOLDOWN_SECONDS);
      return d;
    } catch (e) {
      if (isCode(e, 'rate_limited')) {
        cooldown.start((e as ApiError).retryAfter ?? VERIFY_COOLDOWN_SECONDS);
        setVerifyNote(friendlyMessage(e));
        setAnnounce('Checking is rate limited.');
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

  const cancelRotation = useAction(async () => {
    const d = await api.cancelDkimRotation(domainId);
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
  const progress = recordProgress(domain.records);
  const keys: DkimKeyInfo[] = domain.dkimKeys?.length ? domain.dkimKeys : [domain.dkim];
  // The signing key is the active one; a key that is neither active nor retired is a pending rotation.
  const signing = keys.find((k) => k.active) ?? domain.dkim;
  const pending = domain.dkimKeys ? keys.filter((k) => !k.active && !k.retiredAt) : [];

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

      <Card title="Setup" id="setup">
        <div class="readiness">
          <div>
            <div class="readiness-state" data-testid="ready-state">
              {domain.readyToSend ? <Chip tone="ok">Ready to send</Chip> : <Chip tone="warn">Not ready to send</Chip>}
            </div>
            <p class="small" data-testid="record-progress">
              Required records: {progress.requiredOk} of {progress.requiredTotal} published.
              {progress.recommendedTotal > 0 && ` Recommended records: ${progress.recommendedOk} of ${progress.recommendedTotal} published.`}
            </p>
          </div>
          <div class="readiness-actions">
            <Button variant="primary" onClick={() => void verify.run()} busy={verify.busy} disabled={coolingDown}>
              {coolingDown ? `Check again in ${cooldown.remaining} s` : 'Check DNS'}
            </Button>
          </div>
        </div>
        <p class="hint">
          Publish the records below at your DNS provider, then choose Check DNS: EggMail looks every record up and shows what it found. A check is limited to once every 30
          seconds per domain; EggMail also re-checks automatically. Mail can be sent once the required records are published; the recommended ones improve delivery.
        </p>
      </Card>

      <Card title="Verification">
        <KeyValue
          items={[
            ['Status', <DomainStatusChip status={domain.status} />],
            ['Last checked', domain.lastCheckedAt ? `${formatDateTime(domain.lastCheckedAt)} (${formatRelative(domain.lastCheckedAt)})` : 'Not checked yet'],
            ['Next check', domain.nextCheckAt ? `${formatDateTime(domain.nextCheckAt)} (${formatRelative(domain.nextCheckAt)})` : '-'],
            ['Last error', domain.lastError ?? 'None'],
          ]}
        />
      </Card>

      <Card title="DNS records">
        <DnsRecordsTable records={domain.records} />
      </Card>

      {publishing && (
        <Card title="Zone file">
          <ZoneFileBlock text={publishing.zoneFile} />
        </Card>
      )}

      {publishing?.mtaStsPolicy && (
        <Card title="MTA-STS policy file">
          <p>
            EggMail serves this file itself at <code data-testid="mta-sts-url">{publishing.mtaStsPolicy.url}</code>. The name <code>{publishing.mtaStsPolicy.host}</code> must point at this server
            (the MTA-STS host record above), and the HTTPS certificate the server presents must cover it.
          </p>
          <div class="value-cell">
            <span class="label">Served policy</span>
            <CopyButton text={publishing.mtaStsPolicy.content} what="MTA-STS policy" />
          </div>
          <pre class="zone-file" data-testid="mta-sts-policy" tabIndex={0}>
            {publishing.mtaStsPolicy.content}
          </pre>
        </Card>
      )}
      <DnsHints />

      <Card
        title="DKIM key"
        actions={
          <>
            {pending.length > 0 && <Button onClick={() => setCancelling(true)}>Cancel pending rotation</Button>}
            <Button onClick={() => setRotating(true)}>Rotate DKIM key</Button>
          </>
        }
      >
        <KeyValue
          items={[
            ['Selector', <code>{signing.selector}</code>],
            ['Active', signing.active ? 'Yes' : 'No'],
            ['Created', formatDateTime(signing.createdAt)],
          ]}
        />
        {pending.length > 0 && (
          <Notice tone="info" title="Key rotation pending">
            <p>
              The new selector {pending.map((k) => k.selector).join(', ')} is published as advice but does not sign yet: the current key keeps signing until the new record is found in DNS. You can cancel the
              rotation while it is pending; the unused key is deleted.
            </p>
          </Notice>
        )}
        <div class="stack">
          <span class="label">Public key (RSA-2048)</span>
          <div class="value-cell">
            <code class="dns-value" data-testid="dkim-public-key">
              {signing.publicKey}
            </code>
            <CopyButton text={signing.publicKey} what="DKIM public key" />
          </div>
        </div>
        {keys.length > 1 && (
          <div class="table-wrap">
            <table>
              <caption class="sr-only">All DKIM keys of this domain</caption>
              <thead>
                <tr>
                  <th scope="col">Selector</th>
                  <th scope="col">State</th>
                  <th scope="col">Created</th>
                  <th scope="col">Retired</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.selector}>
                    <th scope="row">
                      <code>{k.selector}</code>
                    </th>
                    <td>{k.active ? <Chip tone="ok">Signing</Chip> : k.retiredAt ? <Chip tone="neutral">Retired</Chip> : <Chip tone="info">Waiting for DNS</Chip>}</td>
                    <td>{formatDateTime(k.createdAt)}</td>
                    <td>{k.retiredAt ? formatDateTime(k.retiredAt) : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {rotate.error !== undefined && !rotating && <ErrorNotice error={rotate.error} />}
        {cancelRotation.error !== undefined && !cancelling && <ErrorNotice error={cancelRotation.error} />}
      </Card>

      {cancelling && (
        <ConfirmDialog
          title="Cancel the pending key rotation?"
          confirmLabel="Cancel rotation"
          busy={cancelRotation.busy}
          error={cancelRotation.error}
          onCancel={() => {
            cancelRotation.clearError();
            setCancelling(false);
          }}
          onConfirm={async () => {
            const d = await cancelRotation.run();
            if (d) setCancelling(false);
          }}
        >
          <p>The new key is deleted and its DNS record is no longer needed. The current key keeps signing. Selector names are never reused, so a later rotation uses a new name.</p>
        </ConfirmDialog>
      )}

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
