import { useEffect, useState } from 'preact/hooks';
import { ApiError } from '../api/client';
import { api } from '../api/endpoints';
import { fieldErrors } from '../api/errorMessages';
import type { Suppression } from '../api/types';
import { Button, Card, Chip, ConfirmDialog, EmptyState, ErrorNotice, Field, LoadMore, Loading, Notice, PageHeader, TextField } from '../components/ui';
import { formatDateTime } from '../lib/format';
import { useAction, useDocumentTitle } from '../lib/hooks';

const EMAIL_RE = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
const REASONS = ['manual', 'bounce', 'complaint'] as const;

export default function Suppressions(_props: Record<string, unknown>) {
  useDocumentTitle('Suppressions');
  const [items, setItems] = useState<Suppression[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<unknown>(undefined);
  const [filter, setFilter] = useState('');
  const [address, setAddress] = useState('');
  const [reason, setReason] = useState<string>('manual');
  const [clientError, setClientError] = useState<string | undefined>();
  const [toRemove, setToRemove] = useState<Suppression | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const loadPage = useAction(async (next: string | undefined, replace: boolean) => {
    const page = await api.suppressions(next);
    setItems((prev) => (replace ? page.items : [...prev, ...page.items]));
    setCursor(page.next_cursor ?? null);
    return true;
  });

  const loadFirst = async () => {
    setLoading(true);
    setLoadError(undefined);
    try {
      const page = await api.suppressions(undefined);
      setItems(page.items);
      setCursor(page.next_cursor ?? null);
    } catch (e) {
      setLoadError(e);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    void loadFirst();
  }, []);

  const add = useAction(async () => api.addSuppression(address.trim().toLowerCase(), reason));
  const remove = useAction(async (addr: string) => {
    try {
      await api.removeSuppression(addr);
    } catch (e) {
      // Already gone: the goal is reached.
      if (!(e instanceof ApiError && e.status === 404)) throw e;
    }
    return true;
  });

  const submit = async (e: Event) => {
    e.preventDefault();
    const a = address.trim();
    const problem = !a ? 'Enter an email address.' : !EMAIL_RE.test(a) ? 'Enter a valid email address.' : undefined;
    setClientError(problem);
    if (problem) return;
    const created = await add.run();
    if (created) {
      setItems((prev) => [created, ...prev.filter((s) => s.address !== created.address)]);
      setStatus(`${created.address} is on the suppression list.`);
      setAddress('');
    }
  };

  const q = filter.trim().toLowerCase();
  const shown = q ? items.filter((s) => s.address.toLowerCase().includes(q) || s.reason.toLowerCase().includes(q)) : items;
  const serverErrors = fieldErrors(add.error);

  return (
    <>
      <PageHeader title="Suppressions" subtitle="Addresses EggMail will not send to. Suppressions have no expiry." />
      <Card title="Add an address">
        <form class="form-grid" onSubmit={submit} noValidate>
          <TextField
            label="Email address"
            type="email"
            value={address}
            onInput={(v) => {
              setAddress(v);
              setClientError(undefined);
            }}
            error={clientError ?? serverErrors.address}
            autocomplete="off"
          />
          <Field label="Reason" error={serverErrors.reason}>
            {({ id, describedBy, invalid }) => (
              <select id={id} value={reason} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => setReason((e.currentTarget as HTMLSelectElement).value)}>
                {REASONS.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <div>
            <Button type="submit" variant="primary" busy={add.busy}>
              Add to suppression list
            </Button>
          </div>
        </form>
        {add.error !== undefined && !serverErrors.address && !serverErrors.reason && <ErrorNotice error={add.error} />}
        {status && <Notice tone="ok">{status}</Notice>}
      </Card>

      <Card title="Suppressed addresses">
        <div class="stack">
          <TextField label="Filter loaded addresses" type="search" value={filter} onInput={setFilter} autocomplete="off" hint={cursor ? 'The filter applies to loaded entries only. Load more to search further.' : undefined} />
          {loading && <Loading />}
          {loadError !== undefined && <ErrorNotice error={loadError} onRetry={() => void loadFirst()} />}
          {loadPage.error !== undefined && <ErrorNotice error={loadPage.error} />}
          {!loading && loadError === undefined && items.length === 0 && (
            <EmptyState title="The suppression list is empty">
              <p>Addresses are added automatically after hard bounces and complaints, or manually above.</p>
            </EmptyState>
          )}
          {!loading && items.length > 0 && shown.length === 0 && <p class="muted">No loaded address matches the filter.</p>}
          {shown.length > 0 && (
            <div class="table-wrap">
              <table>
                <caption class="sr-only">Suppressed addresses</caption>
                <thead>
                  <tr>
                    <th scope="col">Address</th>
                    <th scope="col">Reason</th>
                    <th scope="col">Added</th>
                    <th scope="col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((s) => (
                    <tr key={s.address}>
                      <td class="wrap">{s.address}</td>
                      <td>
                        <Chip tone={s.reason === 'manual' ? 'neutral' : 'warn'}>{s.reason}</Chip>
                      </td>
                      <td>{formatDateTime(s.createdAt)}</td>
                      <td>
                        <Button class="btn-small" onClick={() => setToRemove(s)} aria-label={`Remove ${s.address}`}>
                          Remove
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <LoadMore hasMore={!!cursor} busy={loadPage.busy} onClick={() => void loadPage.run(cursor ?? undefined, false)} />
        </div>
      </Card>

      {toRemove && (
        <ConfirmDialog
          title="Remove from the suppression list?"
          confirmLabel="Remove address"
          danger={false}
          busy={remove.busy}
          error={remove.error}
          onCancel={() => {
            remove.clearError();
            setToRemove(null);
          }}
          onConfirm={async () => {
            const ok = await remove.run(toRemove.address);
            if (ok) {
              setItems((prev) => prev.filter((s) => s.address !== toRemove.address));
              setStatus(`${toRemove.address} was removed. Mail to it will be attempted again.`);
              setToRemove(null);
            }
          }}
        >
          <p>
            <strong>{toRemove.address}</strong> will receive mail again. If it bounced or complained before, it may do so again and hurt your sender reputation.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
