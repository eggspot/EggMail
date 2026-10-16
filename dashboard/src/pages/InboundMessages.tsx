import { useEffect, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import type { Domain, InboundMessageQuery, InboundMessageSummary, InboundVerdictWord } from '../api/types';
import { Button, Card, Chip, ConfirmDialog, EmptyState, ErrorNotice, Field, LoadMore, Loading, Notice, PageHeader, TextField } from '../components/ui';
import { formatBytes, formatDateTime, formatNumber, formatRelative, toIsoOrUndefined } from '../lib/format';
import { useAction, useApi, useDocumentTitle } from '../lib/hooks';
import { ACTION_KINDS, VERDICTS, actionLabel, stateTone, verdictTone } from '../lib/inbound';
import { useApp } from '../state/app';

const PAGE_SIZE = 25;

interface SearchForm {
  domainId: string;
  recipient: string;
  sender: string;
  subject: string;
  action: string;
  state: string;
  dmarc: string;
  flagged: boolean;
  from: string;
  to: string;
}
const emptyForm: SearchForm = { domainId: '', recipient: '', sender: '', subject: '', action: '', state: '', dmarc: '', flagged: false, from: '', to: '' };

function toQuery(f: SearchForm): InboundMessageQuery {
  return {
    domainId: f.domainId || undefined,
    recipient: f.recipient.trim() || undefined,
    sender: f.sender.trim() || undefined,
    subject: f.subject.trim() || undefined,
    action: (f.action || undefined) as InboundMessageQuery['action'],
    state: (f.state || undefined) as InboundMessageQuery['state'],
    dmarc: (f.dmarc || undefined) as InboundVerdictWord | undefined,
    dmarcFlagged: f.flagged ? true : undefined,
    from: toIsoOrUndefined(f.from),
    to: toIsoOrUndefined(f.to),
  };
}

function hasFilter(q: InboundMessageQuery): boolean {
  return Object.values(q).some((v) => v !== undefined);
}

export function VerdictChip({ label, result, title }: { label: string; result: InboundVerdictWord; title?: string }) {
  return (
    <Chip tone={verdictTone(result)} title={title}>
      {label} {result}
    </Chip>
  );
}

function UsageCard() {
  const usage = useApi(() => api.inboundUsage(), []);
  if (usage.error !== undefined) return <ErrorNotice error={usage.error} onRetry={usage.reload} />;
  if (!usage.data) return <Loading label="Loading usage" />;
  const u = usage.data;
  return (
    <Card title="Stored mail">
      <dl class="kv" data-testid="inbound-usage">
        <div>
          <dt>Messages</dt>
          <dd>{formatNumber(u.messages)}</dd>
        </div>
        <div>
          <dt>Stored</dt>
          <dd>{formatBytes(u.bodyBytes)}</dd>
        </div>
        <div>
          <dt>Waiting for their action</dt>
          <dd>
            {formatNumber(u.pending)}
            {u.oldestPendingAt && <span class="muted"> (oldest {formatRelative(u.oldestPendingAt)})</span>}
          </dd>
        </div>
        <div>
          <dt>Action failed</dt>
          <dd>{u.failed > 0 ? <Chip tone="bad">{formatNumber(u.failed)}</Chip> : formatNumber(u.failed)}</dd>
        </div>
      </dl>
    </Card>
  );
}

function Search() {
  const domains = useApi<Domain[]>(() => api.domains(), []);
  const [form, setForm] = useState<SearchForm>(emptyForm);
  const [applied, setApplied] = useState<InboundMessageQuery>({});
  const [items, setItems] = useState<InboundMessageSummary[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(undefined);
  const [moreBusy, setMoreBusy] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(undefined);
  const [searched, setSearched] = useState(false);
  const [tick, setTick] = useState(0);
  const [erasing, setErasing] = useState(false);
  const [erased, setErased] = useState<number | null>(null);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(undefined);
    setMoreError(undefined);
    api
      .inboundMessages({ ...applied, limit: PAGE_SIZE })
      .then((page) => {
        if (!live) return;
        setItems(page.items);
        setNext(page.next_cursor ?? null);
      })
      .catch((e) => live && setError(e))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [applied, tick]);

  const loadMore = async () => {
    if (!next) return;
    setMoreBusy(true);
    setMoreError(undefined);
    try {
      const page = await api.inboundMessages({ ...applied, limit: PAGE_SIZE, cursor: next });
      setItems((cur) => [...cur, ...page.items]);
      setNext(page.next_cursor ?? null);
    } catch (e) {
      setMoreError(e);
    } finally {
      setMoreBusy(false);
    }
  };

  const erase = useAction(async () => {
    const r = await api.eraseInboundMessages(applied);
    setErased(r.deleted);
    setErasing(false);
    setTick((t) => t + 1);
  });

  const set = <K extends keyof SearchForm>(k: K) => (v: SearchForm[K]) => setForm((f) => ({ ...f, [k]: v }));
  const submit = (e: Event) => {
    e.preventDefault();
    setSearched(true);
    setErased(null);
    setApplied(toQuery(form));
  };
  const reset = () => {
    setForm(emptyForm);
    setSearched(false);
    setErased(null);
    setApplied({});
  };
  const filtered = hasFilter(applied);

  return (
    <>
      <Card title="Search">
        <form onSubmit={submit} role="search" aria-label="Search received messages" class="stack">
          <div class="form-grid">
            <Field label="Domain">
              {({ id }) => (
                <select id={id} value={form.domainId} onChange={(e) => set('domainId')((e.currentTarget as HTMLSelectElement).value)}>
                  <option value="">Any domain</option>
                  {(domains.data ?? []).map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <TextField label="Recipient" value={form.recipient} onInput={set('recipient')} placeholder="support@example.com" autocomplete="off" />
            <TextField label="Sender" value={form.sender} onInput={set('sender')} placeholder="alice@sender.test" autocomplete="off" />
            <TextField label="Subject contains" value={form.subject} onInput={set('subject')} autocomplete="off" />
            <Field label="Action">
              {({ id }) => (
                <select id={id} value={form.action} onChange={(e) => set('action')((e.currentTarget as HTMLSelectElement).value)}>
                  <option value="">Any action</option>
                  {ACTION_KINDS.map((a) => (
                    <option key={a.value} value={a.value}>
                      {a.label}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <Field label="Action state">
              {({ id }) => (
                <select id={id} value={form.state} onChange={(e) => set('state')((e.currentTarget as HTMLSelectElement).value)}>
                  <option value="">Any state</option>
                  <option value="pending">Waiting</option>
                  <option value="done">Done</option>
                  <option value="failed">Failed</option>
                </select>
              )}
            </Field>
            <Field label="DMARC">
              {({ id }) => (
                <select id={id} value={form.dmarc} onChange={(e) => set('dmarc')((e.currentTarget as HTMLSelectElement).value)}>
                  <option value="">Any result</option>
                  {VERDICTS.map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <TextField label="Received from" type="datetime-local" value={form.from} onInput={set('from')} />
            <TextField label="Received until" type="datetime-local" value={form.to} onInput={set('to')} />
          </div>
          <div class="check">
            <input id="inbound-flagged" type="checkbox" checked={form.flagged} onChange={(e) => set('flagged')((e.currentTarget as HTMLInputElement).checked)} />
            <label for="inbound-flagged">Only messages flagged for failing DMARC</label>
          </div>
          <div class="row">
            <Button type="submit" variant="primary" busy={loading}>
              Search
            </Button>
            <Button onClick={reset}>Clear</Button>
            {filtered && (
              <Button variant="danger" onClick={() => setErasing(true)}>
                Delete matching messages
              </Button>
            )}
          </div>
        </form>
      </Card>

      {erased !== null && <Notice tone="ok">{erased === 1 ? '1 message was deleted.' : `${formatNumber(erased)} messages were deleted.`}</Notice>}

      <section aria-label="Results" aria-live="polite">
        {loading && <Loading label="Searching" />}
        {!loading && error !== undefined && <ErrorNotice error={error} onRetry={() => setTick((t) => t + 1)} />}
        {!loading && error === undefined && items.length === 0 && (
          <EmptyState title={searched ? 'No messages match' : 'No received messages'}>
            {searched ? <p>Try fewer filters or a wider time range.</p> : <p>Mail sent to a domain you enabled for receiving shows up here, newest first.</p>}
          </EmptyState>
        )}
        {!loading && error === undefined && items.length > 0 && (
          <div class="card">
            <div class="table-wrap">
              <table>
                <caption class="sr-only">Received messages, newest first</caption>
                <thead>
                  <tr>
                    <th scope="col">Received</th>
                    <th scope="col">Subject</th>
                    <th scope="col">From</th>
                    <th scope="col">To</th>
                    <th scope="col">Checks</th>
                    <th scope="col">Action</th>
                    <th scope="col" class="num">
                      Size
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((m) => (
                    <tr key={m.id}>
                      <td>
                        <time dateTime={m.receivedAt}>{formatDateTime(m.receivedAt)}</time>
                      </td>
                      <td class="wrap">
                        <a href={`/inbound/messages/${m.id}`}>{m.subject || '(no subject)'}</a>
                        {m.dmarcFlagged && (
                          <>
                            {' '}
                            <Chip tone="warn" title="The message failed the sender's DMARC policy and was accepted flagged">
                              DMARC flagged
                            </Chip>
                          </>
                        )}
                      </td>
                      <td class="wrap">{m.from || <span class="muted">(bounce)</span>}</td>
                      <td class="wrap">{m.to}</td>
                      <td>
                        <div class="chips">
                          <VerdictChip label="SPF" result={m.auth.spf.result} />
                          <VerdictChip label="DKIM" result={m.auth.dkim.result} />
                          <VerdictChip label="DMARC" result={m.auth.dmarc.result} />
                        </div>
                      </td>
                      <td>
                        <Chip tone={stateTone(m.action.state)}>
                          {actionLabel(m.action.kind)}: {m.action.state === 'pending' ? 'waiting' : m.action.state}
                        </Chip>
                      </td>
                      <td class="num">{formatBytes(m.size)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {moreError !== undefined && <ErrorNotice error={moreError} onRetry={loadMore} />}
            <LoadMore hasMore={!!next} busy={moreBusy} onClick={loadMore} />
          </div>
        )}
      </section>

      {erasing && (
        <ConfirmDialog
          title="Delete every matching message?"
          confirmLabel="Delete messages"
          requirePhrase="delete"
          busy={erase.busy}
          error={erase.error}
          onCancel={() => {
            erase.clearError();
            setErasing(false);
          }}
          onConfirm={() => void erase.run()}
        >
          <p>
            This deletes <strong>all</strong> received messages that match the filters you applied, including their stored copies, and cannot be undone. Use it for an erasure request
            (a sender, a recipient) or to clear a domain's test mail. Messages whose action is still waiting are deleted too.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}

export default function InboundMessages() {
  useDocumentTitle('Inbound mail');
  const { capabilities } = useApp();
  if (capabilities && !capabilities.inbound?.enabled) {
    return (
      <>
        <PageHeader title="Inbound mail" />
        <EmptyState title="Inbound mail is not enabled on this server">
          <p>
            The operator switches it on with <code>Inbound:Enabled</code>. Until then no mail is received. You can prepare the routes of a domain on its inbound page.
          </p>
        </EmptyState>
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Inbound mail"
        subtitle={
          <>
            Mail received for your domains. Turn receiving on and manage the routes on the inbound page of each <a href="/domains">domain</a>.
          </>
        }
      />
      <UsageCard />
      <Search />
    </>
  );
}
