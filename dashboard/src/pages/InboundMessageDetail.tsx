import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { useLocation } from 'preact-iso';
import { api } from '../api/endpoints';
import { isCode } from '../api/errorMessages';
import type { InboundAttachment, InboundMessageDetail as Detail, InboundVerdict } from '../api/types';
import { MessageHtmlFrame } from '../components/MessageHtmlFrame';
import { Button, Card, Chip, ConfirmDialog, EmptyState, ErrorNotice, KeyValue, Loading, Notice, PageHeader, StatusChip, Tabs } from '../components/ui';
import { saveBlob, safeFileName } from '../lib/download';
import { formatBytes, formatDateTime } from '../lib/format';
import { useAction, useApi, useDocumentTitle } from '../lib/hooks';
import { actionLabel, canRetry, explainActionCode, stateTone, verdictTone } from '../lib/inbound';

type TabId = 'text' | 'html' | 'headers' | 'attachments';

function VerdictRow({ name, v, extra }: { name: string; v: InboundVerdict; extra?: string }) {
  return (
    <tr>
      <th scope="row">{name}</th>
      <td>
        <Chip tone={verdictTone(v.result)}>{v.result}</Chip>
      </td>
      <td class="wrap">{extra ?? v.domain ?? ''}</td>
    </tr>
  );
}

function Verdicts({ m }: { m: Detail }) {
  const a = m.auth;
  return (
    <div class="table-wrap">
      <table>
        <caption class="sr-only">Checks the server made when the message arrived</caption>
        <thead>
          <tr>
            <th scope="col">Check</th>
            <th scope="col">Result</th>
            <th scope="col">For</th>
          </tr>
        </thead>
        <tbody>
          <VerdictRow name="SPF (sender address)" v={a.spf} />
          <VerdictRow name="SPF (HELO name)" v={a.spfHelo} extra={m.helo ?? ''} />
          <VerdictRow name="DKIM" v={a.dkim} />
          <VerdictRow name="DMARC" v={a.dmarc} extra={a.dmarc.policy ? `the sender's policy: ${a.dmarc.policy}` : ''} />
          <VerdictRow name="ARC" v={a.arc} />
        </tbody>
      </table>
    </div>
  );
}

function ActionCard({ m, onRetried }: { m: Detail; onRetried: () => void }) {
  const a = m.action;
  const retry = useAction(async () => {
    await api.retryInboundMessage(m.id);
    onRetried();
  });
  const stale = a.currentKind && a.currentKind !== a.kind;
  const error = explainActionCode(a.lastError);
  const note = explainActionCode(a.note);
  return (
    <Card title="Action">
      <KeyValue
        items={[
          ['What was set when it arrived', actionLabel(a.kind)],
          ...(stale ? ([['What the route does now', actionLabel(a.currentKind)]] as [string, string][]) : []),
          ['State', <Chip tone={stateTone(a.state)}>{a.state === 'pending' ? 'waiting' : a.state}</Chip>],
          ['Attempts', String(a.attempts)],
          ...(a.state === 'pending' && a.nextAttemptAt ? ([['Next attempt', formatDateTime(a.nextAttemptAt)]] as [string, string][]) : []),
          ...(a.finishedAt ? ([['Finished', formatDateTime(a.finishedAt)]] as [string, string][]) : []),
          ...(a.retryGeneration > 0 ? ([['Sent again by hand', `${a.retryGeneration} time${a.retryGeneration === 1 ? '' : 's'}`]] as [string, string][]) : []),
          ...(a.forwardMessageId ? ([['Forwarded copy', <a href={`/messages/${a.forwardMessageId}`}>open the outbound message</a>]] as [string, ComponentChildren][]) : []),
        ]}
      />
      {stale && (
        <Notice tone="info">The route was changed after this message arrived. The action that runs is the route's current one.</Notice>
      )}
      {a.lastError && (
        <Notice tone={a.state === 'failed' ? 'bad' : 'warn'} title={a.state === 'failed' ? 'The action failed' : 'The last attempt failed'}>
          <code>{a.lastError}</code>
          {error && <p>{error}</p>}
        </Notice>
      )}
      {a.note && (
        <Notice tone="info">
          <code>{a.note}</code>
          {note && <p>{note}</p>}
        </Notice>
      )}
      {retry.error !== undefined && <ErrorNotice error={retry.error} title="The action was not queued again" />}
      {canRetry(m) && (
        <div class="row">
          <Button onClick={() => void retry.run()} busy={retry.busy}>
            Retry the action
          </Button>
          <span class="muted small">Starts a new series of attempts; a webhook receiver gets it as a new event.</span>
        </div>
      )}
    </Card>
  );
}

function AttachmentTable({ id, items }: { id: string; items: InboundAttachment[] }) {
  const [error, setError] = useState<unknown>(undefined);
  const [busy, setBusy] = useState<number | null>(null);
  const fetchOne = async (a: InboundAttachment) => {
    setBusy(a.index);
    setError(undefined);
    try {
      saveBlob(await api.downloadInboundAttachment(id, a.index), safeFileName(a.filename, `attachment-${a.index}`));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };
  if (items.length === 0) return <p class="muted">This message has no attachments.</p>;
  return (
    <div class="stack">
      <Notice tone="info">Attachments are downloaded, never opened here. Treat them as untrusted files.</Notice>
      {error !== undefined && <ErrorNotice error={error} />}
      <div class="table-wrap">
        <table>
          <caption class="sr-only">Attachments</caption>
          <thead>
            <tr>
              <th scope="col">File name</th>
              <th scope="col">Type (as claimed)</th>
              <th scope="col" class="num">
                Size
              </th>
              <th scope="col">
                <span class="sr-only">Download</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.index}>
                <td class="wrap">
                  {a.filename ?? <span class="muted">(no name)</span>} {a.disposition === 'inline' && <Chip>inline</Chip>}
                </td>
                <td class="wrap">{a.content_type}</td>
                <td class="num">{formatBytes(a.size)}</td>
                <td>
                  <Button class="btn-small" busy={busy === a.index} onClick={() => void fetchOne(a)} aria-label={`Download ${a.filename ?? `attachment ${a.index + 1}`}`}>
                    Download
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Content({ m }: { m: Detail }) {
  const c = m.content;
  const [tab, setTab] = useState<TabId>('text');
  if (c.state === 'no_body') {
    return (
      <Notice tone="info" title="The message itself is not kept">
        The stored copy is gone: this message was discarded by its route, it was forwarded (the copy now lives in the outbound queue), or it expired. Only the record of its arrival is left.
      </Notice>
    );
  }
  const tabs = [
    { id: 'text', label: 'Text' },
    { id: 'html', label: 'HTML (sandboxed)' },
    { id: 'headers', label: `Headers (${c.headers.length})` },
    { id: 'attachments', label: `Attachments (${c.attachments.length})` },
  ];
  return (
    <>
      {c.truncated && (
        <Notice tone="warn" title="Shown cut short">
          The text or the HTML was cut at 256 KiB for display. The stored message is complete: download it to see everything.
        </Notice>
      )}
      <Tabs tabs={tabs} active={tab} onChange={(t) => setTab(t as TabId)} label="Message content" />
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} tabIndex={0}>
        {tab === 'text' &&
          (c.text ? (
            <pre class="text-view" data-testid="text-view">
              {c.text}
            </pre>
          ) : (
            <p class="muted">This message has no plain-text part.{c.html ? ' Open the HTML tab.' : ''}</p>
          ))}
        {tab === 'html' &&
          (c.html ? (
            <MessageHtmlFrame html={c.html} title="Received message HTML (sandboxed)" />
          ) : (
            <p class="muted">This message has no HTML part.</p>
          ))}
        {tab === 'headers' && (
          <div class="table-wrap">
            <table>
              <caption class="sr-only">Header fields of the stored message</caption>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Value</th>
                </tr>
              </thead>
              <tbody>
                {c.headers.map((h, i) => (
                  <tr key={`${h.name}-${i}`}>
                    <th scope="row" class="wrap">
                      {h.name}
                    </th>
                    <td class="wrap">{h.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {tab === 'attachments' && <AttachmentTable id={m.id} items={c.attachments} />}
      </div>
    </>
  );
}

export default function InboundMessageDetail({ id }: { id?: string }) {
  const messageId = id ?? '';
  const location = useLocation();
  const { data: m, error, loading, reload } = useApi(() => api.inboundMessage(messageId), [messageId]);
  useDocumentTitle(m?.subject || 'Received message');
  const [deleting, setDeleting] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(undefined);
  const remove = useAction(async () => {
    await api.deleteInboundMessage(messageId);
    location.route('/inbound');
  });

  if (loading && !m) return <Loading label="Loading message" />;
  if (isCode(error, 'not_found')) {
    return (
      <EmptyState title="Message not found" action={<a href="/inbound">Back to inbound mail</a>}>
        <p>It may have been deleted, or it is older than the retention.</p>
      </EmptyState>
    );
  }
  if (error !== undefined && !m) return <ErrorNotice error={error} onRetry={reload} />;
  if (!m) return null;

  const downloadRaw = async () => {
    setSaveError(undefined);
    try {
      saveBlob(await api.downloadInboundRaw(m.id), `${m.id}.eml`);
    } catch (e) {
      setSaveError(e);
    }
  };

  return (
    <>
      <PageHeader
        title={m.subject || '(no subject)'}
        subtitle={<a href="/inbound">All received messages</a>}
        actions={
          <>
            {m.hasRaw && <Button onClick={() => void downloadRaw()}>Download message (.eml)</Button>}
            <Button variant="danger" onClick={() => setDeleting(true)}>
              Delete
            </Button>
          </>
        }
      />
      {saveError !== undefined && <ErrorNotice error={saveError} title="The download failed" />}
      {m.dmarcFlagged && (
        <Notice tone="warn" title="Flagged: failed the sender's DMARC policy">
          The sender's domain asks receivers to quarantine or reject mail like this, and this domain is set to flag it. The message was accepted and is kept; the header <code>X-EggMail-Dmarc: flagged</code> was added.
        </Notice>
      )}
      <Card title="Message">
        <KeyValue
          items={[
            ['Received', <time dateTime={m.receivedAt}>{formatDateTime(m.receivedAt)}</time>],
            ['Domain', m.domain],
            ['Envelope from', m.from || '(null sender: a bounce)'],
            ['Envelope to', m.to],
            ['Connected from', `${m.remoteIp}${m.helo ? ` (said ${m.helo})` : ''}`],
            ['Encryption', m.tls ? <StatusChip status="ok" label="TLS" /> : <Chip tone="warn">No TLS</Chip>],
            ['Size', formatBytes(m.size)],
            ['Route', m.routeId ? <code>{m.routeId}</code> : 'none (postmaster is accepted and stored)'],
          ]}
        />
      </Card>
      <Card title="Checks">
        <Verdicts m={m} />
        <p class="muted small">Every field of a received message is written by the sender. Nothing here is trusted or interpreted; HTML only renders in a sandbox with remote content blocked.</p>
      </Card>
      <ActionCard m={m} onRetried={reload} />
      <Card title="Content">
        <Content m={m} />
      </Card>
      {deleting && (
        <ConfirmDialog
          title="Delete this message?"
          confirmLabel="Delete message"
          busy={remove.busy}
          error={remove.error}
          onCancel={() => {
            remove.clearError();
            setDeleting(false);
          }}
          onConfirm={() => void remove.run()}
        >
          <p>The message and its stored copy are removed at once, whatever its action state. This cannot be undone.</p>
        </ConfirmDialog>
      )}
    </>
  );
}
