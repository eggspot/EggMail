import { useState } from 'preact/hooks';
import { useLocation } from 'preact-iso';
import { api } from '../api/endpoints';
import { fieldErrors } from '../api/errorMessages';
import { DomainStatusChip } from '../components/DnsRecordsTable';
import { Button, Card, Chip, ConfirmDialog, EmptyState, ErrorNotice, Loading, PageHeader, TextField } from '../components/ui';
import { formatRelative } from '../lib/format';
import { useAction, useApi, useDocumentTitle } from '../lib/hooks';
import type { Domain } from '../api/types';

const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export function validateDomainName(value: string): string | undefined {
  const v = value.trim();
  if (!v) return 'Enter a domain name.';
  if (!HOST_RE.test(v)) return 'Enter a valid domain name such as mail.example.com (no scheme, path or spaces).';
  return undefined;
}

export default function Domains(_props: Record<string, unknown>) {
  useDocumentTitle('Domains');
  const { route } = useLocation();
  const { data, error, loading, reload } = useApi(() => api.domains(), []);
  const [name, setName] = useState('');
  const [clientError, setClientError] = useState<string | undefined>();
  const [toDelete, setToDelete] = useState<Domain | null>(null);

  const create = useAction(async (n: string) => api.createDomain(n));
  const remove = useAction(async (id: string) => {
    await api.deleteDomain(id);
    return true;
  });

  const submit = async (e: Event) => {
    e.preventDefault();
    const problem = validateDomainName(name);
    setClientError(problem);
    if (problem) return;
    const created = await create.run(name.trim().toLowerCase());
    if (created) {
      setName('');
      route(`/domains/${created.id}`);
    }
  };

  const serverError = fieldErrors(create.error).name;

  return (
    <>
      <PageHeader title="Domains" subtitle="Sending domains must be verified with DNS records before mail can be sent from them." />
      <Card title="Add a domain">
        <form class="form-grid" onSubmit={submit} noValidate>
          <TextField
            label="Domain name"
            value={name}
            onInput={(v) => {
              setName(v);
              setClientError(undefined);
            }}
            error={clientError ?? serverError}
            hint="For example mail.example.com. EggMail creates a DKIM key and shows the DNS records to publish (SPF, DKIM, DMARC, bounce, MTA-STS, TLS-RPT) as a zone file, and checks them for you."
            autocomplete="off"
            spellcheck={false}
          />
          <div>
            <Button type="submit" variant="primary" busy={create.busy}>
              Add domain
            </Button>
          </div>
        </form>
        {create.error !== undefined && !serverError && <ErrorNotice error={create.error} />}
      </Card>

      <Card title="Your domains">
        {loading && !data && <Loading />}
        {error !== undefined && <ErrorNotice error={error} onRetry={reload} />}
        {data && data.length === 0 && (
          <EmptyState title="No domains yet">
            <p>Add your first sending domain above, then publish the DNS records it shows.</p>
          </EmptyState>
        )}
        {data && data.length > 0 && (
          <div class="table-wrap">
            <table>
              <caption class="sr-only">Sending domains</caption>
              <thead>
                <tr>
                  <th scope="col">Domain</th>
                  <th scope="col">Status</th>
                  <th scope="col">Sending</th>
                  <th scope="col">Last checked</th>
                  <th scope="col">
                    <span class="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <a href={`/domains/${d.id}`}>{d.name}</a>
                    </td>
                    <td>
                      <DomainStatusChip status={d.status} />
                    </td>
                    <td>{d.sendingPaused ? <Chip tone="bad">Paused</Chip> : <Chip tone="ok">Active</Chip>}</td>
                    <td>{formatRelative(d.lastCheckedAt)}</td>
                    <td>
                      <Button variant="danger" class="btn-small" onClick={() => setToDelete(d)} aria-label={`Delete ${d.name}`}>
                        Delete
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {toDelete && (
        <ConfirmDialog
          title={`Delete ${toDelete.name}?`}
          confirmLabel="Delete domain"
          requirePhrase={toDelete.name}
          busy={remove.busy}
          error={remove.error}
          onCancel={() => {
            remove.clearError();
            setToDelete(null);
          }}
          onConfirm={async () => {
            const ok = await remove.run(toDelete.id);
            if (ok) {
              setToDelete(null);
              reload();
            }
          }}
        >
          <p>
            Mail can no longer be sent from this domain, and its DKIM key is deleted. DNS records you published stay in your DNS zone and should be removed there too.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
