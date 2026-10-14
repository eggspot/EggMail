import { useEffect, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { isCode } from '../api/errorMessages';
import type { MessageQuery, MessageSummary } from '../api/types';
import { HistoryNotRecorded } from '../components/HistoryGate';
import { Button, EmptyState, ErrorNotice, Field, LoadMore, Loading, PageHeader, StatusChip, TextField, Card } from '../components/ui';
import { formatBytes, formatDateTime, toIsoOrUndefined } from '../lib/format';
import { useDocumentTitle } from '../lib/hooks';
import { MESSAGE_STATUSES } from '../lib/messages';
import { useApp } from '../state/app';

const PAGE_SIZE = 25;

interface SearchForm {
  recipient: string;
  sender: string;
  subject: string;
  status: string;
  from: string;
  to: string;
}
const emptyForm: SearchForm = { recipient: '', sender: '', subject: '', status: '', from: '', to: '' };

function toQuery(f: SearchForm): MessageQuery {
  return {
    recipient: f.recipient.trim() || undefined,
    sender: f.sender.trim() || undefined,
    subject: f.subject.trim() || undefined,
    status: f.status || undefined,
    from: toIsoOrUndefined(f.from),
    to: toIsoOrUndefined(f.to),
    limit: PAGE_SIZE,
  };
}

function RecipientsCell({ recipients, count }: { recipients: string[]; count?: number }) {
  if (!recipients.length) return <>{count ? `${count} recipient${count === 1 ? '' : 's'}` : '-'}</>;
  const [first, ...rest] = recipients;
  // The list only carries the first few recipients; recipientCount is the real number.
  const more = Math.max(rest.length, (count ?? recipients.length) - 1);
  return (
    <>
      {first}
      {more > 0 && (
        <span class="muted" title={rest.join(', ') || undefined}>
          {' '}
          +{more} more
        </span>
      )}
    </>
  );
}

function MessageSearch() {
  const [form, setForm] = useState<SearchForm>(emptyForm);
  const [applied, setApplied] = useState<MessageQuery>({ limit: PAGE_SIZE });
  const [items, setItems] = useState<MessageSummary[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(undefined);
  const [moreBusy, setMoreBusy] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(undefined);
  const [searched, setSearched] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(undefined);
    setMoreError(undefined);
    api
      .searchMessages(applied)
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
      const page = await api.searchMessages({ ...applied, cursor: next });
      setItems((cur) => [...cur, ...page.items]);
      setNext(page.next_cursor ?? null);
    } catch (e) {
      setMoreError(e);
    } finally {
      setMoreBusy(false);
    }
  };

  const set = (k: keyof SearchForm) => (v: string) => setForm((f) => ({ ...f, [k]: v }));
  const submit = (e: Event) => {
    e.preventDefault();
    setSearched(true);
    setApplied(toQuery(form));
  };
  const reset = () => {
    setForm(emptyForm);
    setSearched(false);
    setApplied({ limit: PAGE_SIZE });
  };

  if (isCode(error, 'history_not_recorded')) return <HistoryNotRecorded what="Message search" />;

  return (
    <>
      <Card title="Search">
        <form onSubmit={submit} role="search" aria-label="Search messages" class="stack">
          <div class="form-grid">
            <TextField label="Recipient" value={form.recipient} onInput={set('recipient')} placeholder="alex@example.org" autocomplete="off" />
            <TextField label="Sender" value={form.sender} onInput={set('sender')} placeholder="noreply@example.com" autocomplete="off" />
            <TextField label="Subject contains" value={form.subject} onInput={set('subject')} autocomplete="off" />
            <Field label="Status">
              {({ id }) => (
                <select id={id} value={form.status} onChange={(e) => set('status')((e.currentTarget as HTMLSelectElement).value)}>
                  <option value="">Any status</option>
                  {MESSAGE_STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <TextField label="Received from" type="datetime-local" value={form.from} onInput={set('from')} />
            <TextField label="Received until" type="datetime-local" value={form.to} onInput={set('to')} />
          </div>
          <div class="row">
            <Button type="submit" variant="primary" busy={loading}>
              Search
            </Button>
            <Button onClick={reset}>Clear</Button>
          </div>
        </form>
      </Card>

      <section aria-label="Results" aria-live="polite">
        {loading && <Loading label="Searching" />}
        {!loading && error !== undefined && <ErrorNotice error={error} onRetry={() => setTick((t) => t + 1)} />}
        {!loading && error === undefined && items.length === 0 && (
          <EmptyState title={searched ? 'No messages match' : 'No messages yet'}>
            {searched ? <p>Try fewer filters or a wider time range.</p> : <p>Messages appear here after they are sent through SMTP or the API.</p>}
          </EmptyState>
        )}
        {!loading && error === undefined && items.length > 0 && (
          <div class="card">
            <div class="table-wrap">
              <table>
                <caption class="sr-only">Messages, newest first</caption>
                <thead>
                  <tr>
                    <th scope="col">Received</th>
                    <th scope="col">Subject</th>
                    <th scope="col">From</th>
                    <th scope="col">To</th>
                    <th scope="col">Status</th>
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
                        <a href={`/messages/${m.id}`}>{m.subject || '(no subject)'}</a>
                      </td>
                      <td class="wrap">{m.from}</td>
                      <td class="wrap">
                        <RecipientsCell recipients={m.recipients} count={m.recipientCount} />
                      </td>
                      <td>
                        <StatusChip status={m.status} />
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
    </>
  );
}

export default function Messages() {
  useDocumentTitle('Messages');
  const { historyMode } = useApp();
  return (
    <>
      <PageHeader title="Messages" subtitle="Search delivered, deferred and bounced messages." />
      {historyMode === 'statsonly' ? <HistoryNotRecorded what="Message search" /> : <MessageSearch />}
    </>
  );
}
