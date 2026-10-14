import { useEffect, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { fieldErrors, isCode } from '../api/errorMessages';
import type { Webhook, WebhookAttempt } from '../api/types';
import { CheckboxGroup } from '../components/CheckboxGroup';
import { Button, Card, Chip, ConfirmDialog, EmptyState, ErrorNotice, Loading, Notice, OneTimeSecret, PageHeader, TextField } from '../components/ui';
import { formatDateTime, formatDuration } from '../lib/format';
import { useAction, useApi, useDocumentTitle, usePolling } from '../lib/hooks';

export const WEBHOOK_EVENT_TYPES = ['message.delivered', 'message.deferred', 'message.bounced', 'message.complained', 'message.expired', 'message.suppressed', 'webhook.endpoint.disabled'] as const;

/* ---------- attempts log ---------- */

function StatusCodeChip({ status }: { status: number | null }) {
  if (status === null) return <Chip tone="bad">No response</Chip>;
  return <Chip tone={status >= 200 && status < 300 ? 'ok' : 'bad'}>{status}</Chip>;
}

function AttemptsLog({ webhookId, refreshKey }: { webhookId: string; refreshKey: number }) {
  const { data, error, loading, reload } = useApi(() => api.webhookAttempts(webhookId, 50), [webhookId, refreshKey]);
  const [replaying, setReplaying] = useState<WebhookAttempt | null>(null);
  // A delivery is asynchronous: after a test event or a replay, look again every 2 seconds for up to 20 seconds so the new attempt appears.
  const [watch, setWatch] = useState(refreshKey > 0 ? 10 : 0);
  useEffect(() => {
    if (refreshKey > 0) setWatch(10);
  }, [refreshKey]);
  usePolling(
    () => {
      reload();
      setWatch((n) => n - 1);
      return watch > 1;
    },
    2_000,
    watch > 0,
  );
  const [outcome, setOutcome] = useState<string | null>(null);
  const replay = useAction(async (outboxId: string) => {
    await api.replayWebhookEvent(outboxId);
    return true;
  });

  // The server does not record the event type of an attempt (api.md); show the column only when a response carries it.
  const showEvent = !!data?.some((a) => a.eventType);
  return (
    <div class="stack">
      {loading && !data && <Loading label="Loading attempts" />}
      {error !== undefined && <ErrorNotice error={error} onRetry={reload} />}
      {outcome && <Notice tone="ok">{outcome}</Notice>}
      {data && data.length === 0 && <p class="muted">No delivery attempts yet. Send a test event to see one.</p>}
      {data && data.length > 0 && (
        <div class="table-wrap">
          <table>
            <caption class="sr-only">Delivery attempts, newest first</caption>
            <thead>
              <tr>
                <th scope="col">Time</th>
                {showEvent && <th scope="col">Event</th>}
                <th scope="col">Status</th>
                <th scope="col" class="num">
                  Duration
                </th>
                <th scope="col">Error</th>
                <th scope="col">Response</th>
                <th scope="col">
                  <span class="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.map((a) => (
                <tr key={a.id}>
                  <td>{formatDateTime(a.at)}</td>
                  {showEvent && (
                    <td>
                      <code>{a.eventType ?? '-'}</code>
                    </td>
                  )}
                  <td>
                    <StatusCodeChip status={a.status} />
                  </td>
                  <td class="num">{formatDuration(a.durationMs)}</td>
                  <td>{a.errorClass ?? '-'}</td>
                  <td class="wrap">
                    {a.snippet ? (
                      <details>
                        <summary>Show response</summary>
                        <pre class="text-view">{a.snippet}</pre>
                      </details>
                    ) : (
                      <span class="muted">empty</span>
                    )}
                  </td>
                  <td>
                    <Button class="btn-small" onClick={() => { setOutcome(null); setReplaying(a); }} aria-label={`Replay ${a.eventType ?? 'event'} from ${formatDateTime(a.at)}`}>
                      Replay
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {replaying && (
        <ConfirmDialog
          title="Replay this delivery?"
          confirmLabel="Replay delivery"
          danger={false}
          busy={replay.busy}
          error={isCode(replay.error, 'not_found') ? new Error('Only finished or failed deliveries can be replayed. This one is still waiting for its next retry, or is no longer kept.') : replay.error}
          onCancel={() => {
            replay.clearError();
            setReplaying(null);
          }}
          onConfirm={async () => {
            const ok = await replay.run(replaying.outboxId);
            if (ok) {
              setReplaying(null);
              setOutcome('Delivery re-queued. The new attempt appears in the log shortly.');
              reload();
              setWatch(10);
            }
          }}
        >
          <p>The event is sent to the endpoint again with the same event id. Receivers should de-duplicate by event id.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

/* ---------- one endpoint ---------- */

function EventChips({ types }: { types: string[] }) {
  return (
    <span class="row">
      {types.map((t) => (
        <Chip key={t} tone="neutral">
          {t}
        </Chip>
      ))}
    </span>
  );
}

function EndpointCard({ hook, onChanged, onSecret }: { hook: Webhook; onChanged: () => void; onSecret: (title: string, secret: string) => void }) {
  const [editing, setEditing] = useState(false);
  const [url, setUrl] = useState(hook.url);
  const [events, setEvents] = useState<string[]>(hook.event_types);
  const [showAttempts, setShowAttempts] = useState(false);
  const [attemptsKey, setAttemptsKey] = useState(0);
  const [confirm, setConfirm] = useState<'delete' | 'rotate' | 'previous' | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const save = useAction(async () => {
    await api.updateWebhook(hook.id, { url: url.trim(), event_types: events });
    return true;
  });
  const toggle = useAction(async () => {
    await api.updateWebhook(hook.id, { enabled: !hook.enabled });
    return true;
  });
  const test = useAction(async () => {
    await api.testWebhook(hook.id);
    return true;
  });
  const del = useAction(async () => {
    await api.deleteWebhook(hook.id);
    return true;
  });
  const rotate = useAction(async () => api.rotateWebhookSecret(hook.id));
  const dropPrevious = useAction(async () => {
    await api.removePreviousWebhookSecret(hook.id);
    return true;
  });

  const errs = fieldErrors(save.error);

  return (
    <Card title={hook.url} id={`wh-${hook.id}`}>
      <div class="stack">
        <div class="row">
          <Chip tone={hook.enabled ? 'ok' : 'warn'}>{hook.enabled ? 'Enabled' : 'Disabled'}</Chip>
          <EventChips types={hook.event_types} />
        </div>
        {!hook.enabled && hook.disabledReason && <Notice tone="warn">{hook.disabledReason}</Notice>}
        {hook.secretRotationPending && (
          <Notice tone="info" title="Secret rotation in progress">
            <p>Deliveries are signed with the new secret and the previous one, so a receiver that still uses the old secret keeps working. Remove the previous secret once your receiver uses the new one.</p>
            <Button onClick={() => setConfirm('previous')}>Remove previous secret</Button>
          </Notice>
        )}
        {note && <Notice tone="ok">{note}</Notice>}
        {test.error !== undefined && <ErrorNotice error={test.error} />}
        {toggle.error !== undefined && <ErrorNotice error={toggle.error} />}

        {editing ? (
          <form
            class="stack"
            noValidate
            onSubmit={async (e) => {
              e.preventDefault();
              if (await save.run()) {
                setEditing(false);
                onChanged();
              }
            }}
          >
            <TextField label="Endpoint URL" value={url} onInput={setUrl} error={errs.url} hint="HTTPS only. Internal addresses are blocked unless allowlisted for your tenant." />
            <CheckboxGroup legend="Event types" options={WEBHOOK_EVENT_TYPES} selected={events} onChange={setEvents} error={errs.event_types} />
            {save.error !== undefined && !errs.url && !errs.event_types && <ErrorNotice error={save.error} />}
            <div class="row">
              <Button type="submit" variant="primary" busy={save.busy}>
                Save changes
              </Button>
              <Button
                onClick={() => {
                  setEditing(false);
                  setUrl(hook.url);
                  setEvents(hook.event_types);
                  save.clearError();
                }}
              >
                Cancel
              </Button>
            </div>
          </form>
        ) : (
          <div class="row">
            <Button
              busy={test.busy}
              onClick={async () => {
                setNote(null);
                if (await test.run()) {
                  setNote('Test event sent. See the attempts log for the result.');
                  setShowAttempts(true);
                  setAttemptsKey((k) => k + 1);
                }
              }}
            >
              Send test event
            </Button>
            <Button onClick={() => setEditing(true)}>Edit</Button>
            <Button
              busy={toggle.busy}
              onClick={async () => {
                if (await toggle.run()) onChanged();
              }}
            >
              {hook.enabled ? 'Disable' : 'Enable'}
            </Button>
            <Button onClick={() => setConfirm('rotate')}>Rotate secret</Button>
            <Button variant="danger" onClick={() => setConfirm('delete')}>
              Delete
            </Button>
            <Button aria-expanded={showAttempts} aria-controls={`attempts-${hook.id}`} onClick={() => setShowAttempts(!showAttempts)}>
              {showAttempts ? 'Hide attempts' : 'Show attempts'}
            </Button>
          </div>
        )}

        {showAttempts && (
          <div id={`attempts-${hook.id}`}>
            <h3>Delivery attempts</h3>
            <AttemptsLog webhookId={hook.id} refreshKey={attemptsKey} />
          </div>
        )}
      </div>

      {confirm === 'delete' && (
        <ConfirmDialog
          title="Delete this endpoint?"
          confirmLabel="Delete endpoint"
          busy={del.busy}
          error={del.error}
          onCancel={() => {
            del.clearError();
            setConfirm(null);
          }}
          onConfirm={async () => {
            if (await del.run()) {
              setConfirm(null);
              onChanged();
            }
          }}
        >
          <p>
            Events stop being sent to <code>{hook.url}</code>. Its attempts log is deleted.
          </p>
        </ConfirmDialog>
      )}
      {confirm === 'previous' && (
        <ConfirmDialog
          title="Remove the previous secret?"
          confirmLabel="Remove previous secret"
          busy={dropPrevious.busy}
          error={dropPrevious.error}
          onCancel={() => {
            dropPrevious.clearError();
            setConfirm(null);
          }}
          onConfirm={async () => {
            if (await dropPrevious.run()) {
              setConfirm(null);
              onChanged();
            }
          }}
        >
          <p>From now on deliveries are signed with the new secret only. A receiver that still verifies with the old secret will reject them.</p>
        </ConfirmDialog>
      )}
      {confirm === 'rotate' && (
        <ConfirmDialog
          title="Rotate the signing secret?"
          confirmLabel="Rotate secret"
          danger={false}
          busy={rotate.busy}
          error={rotate.error}
          onCancel={() => {
            rotate.clearError();
            setConfirm(null);
          }}
          onConfirm={async () => {
            const r = await rotate.run();
            if (r?.secret) {
              setConfirm(null);
              onSecret(`New signing secret for ${hook.url}`, r.secret);
              onChanged();
            }
          }}
        >
          <p>
            A new secret is created and shown once. Deliveries are signed with both the old and the new secret until the old one is removed, so you can switch your receiver
            without dropping events.
          </p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

/* ---------- page ---------- */

export default function Webhooks(_props: Record<string, unknown>) {
  useDocumentTitle('Webhooks');
  const { data, error, loading, reload } = useApi(() => api.webhooks(), []);
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState<string[]>(['message.delivered', 'message.bounced']);
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  // One-time secret: lives only in this state until the user confirms they saved it.
  const [secret, setSecret] = useState<{ title: string; value: string } | null>(null);

  const create = useAction(async () => api.createWebhook(url.trim(), events));
  const serverErrors = fieldErrors(create.error);

  const submit = async (e: Event) => {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (!url.trim()) errs.url = 'Enter the endpoint URL.';
    if (events.length === 0) errs.event_types = 'Select at least one event type.';
    setClientErrors(errs);
    if (Object.keys(errs).length) return;
    const created = await create.run();
    if (created) {
      if (created.secret) setSecret({ title: `Signing secret for ${created.url}`, value: created.secret });
      setUrl('');
      reload();
    }
  };

  return (
    <>
      <PageHeader title="Webhooks" subtitle="Signed HTTP callbacks for delivery events (Standard Webhooks signatures)." />
      {secret && (
        <OneTimeSecret
          title={secret.title}
          secret={secret.value}
          onDone={() => setSecret(null)}
          hint="Use it to verify the webhook-signature header of each delivery. Rotating the secret later keeps the old one valid until it is removed."
        />
      )}
      <Card title="Add an endpoint">
        <form class="stack" onSubmit={submit} noValidate>
          <TextField
            label="Endpoint URL"
            value={url}
            onInput={setUrl}
            error={clientErrors.url ?? serverErrors.url}
            hint="HTTPS only. Internal addresses are blocked (SSRF protection) unless allowlisted for your tenant."
            placeholder="your-host.example/hooks/eggmail (https only)"
            autocomplete="off"
            spellcheck={false}
          />
          <CheckboxGroup legend="Event types" options={WEBHOOK_EVENT_TYPES} selected={events} onChange={setEvents} error={clientErrors.event_types ?? serverErrors.event_types} />
          {create.error !== undefined && !serverErrors.url && !serverErrors.event_types && <ErrorNotice error={create.error} />}
          <div>
            <Button type="submit" variant="primary" busy={create.busy}>
              Create endpoint
            </Button>
          </div>
        </form>
      </Card>

      {loading && !data && <Loading />}
      {error !== undefined && <ErrorNotice error={error} onRetry={reload} title={isCode(error, 'forbidden') ? 'Not allowed' : undefined} />}
      {data && data.length === 0 && (
        <EmptyState title="No webhook endpoints">
          <p>Create an endpoint above to receive delivery events.</p>
        </EmptyState>
      )}
      {data?.map((h) => (
        <EndpointCard key={h.id} hook={h} onChanged={reload} onSecret={(title, value) => setSecret({ title, value })} />
      ))}
    </>
  );
}
