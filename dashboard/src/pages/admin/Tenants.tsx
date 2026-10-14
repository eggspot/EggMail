import { useState } from 'preact/hooks';
import { api } from '../../api/endpoints';
import { fieldErrors } from '../../api/errorMessages';
import type { Tenant } from '../../api/types';
import { Button, Card, ConfirmDialog, Dialog, EmptyState, ErrorNotice, Loading, Notice, PageHeader, StatusChip, TextField } from '../../components/ui';
import { formatDateTime } from '../../lib/format';
import { useAction, useApi, useDocumentTitle } from '../../lib/hooks';
import { useApp } from '../../state/app';

function CreateTenant({ onCreated }: { onCreated: (t: Tenant) => void }) {
  const [name, setName] = useState('');
  const create = useAction(async () => {
    const t = await api.createTenant(name.trim());
    setName('');
    onCreated(t);
  });
  const errs = fieldErrors(create.error);
  return (
    <Card title="Create a tenant">
      <form
        class="form-grid"
        onSubmit={(e) => {
          e.preventDefault();
          void create.run();
        }}
        noValidate
      >
        <TextField label="Name" value={name} onInput={setName} error={errs.name} hint="Shown in the tenant picker." maxLength={80} />
        <div>
          <Button type="submit" variant="primary" busy={create.busy} disabled={!name.trim()}>
            Create tenant
          </Button>
        </div>
      </form>
      {create.error !== undefined && !errs.name && <ErrorNotice error={create.error} />}
    </Card>
  );
}

function RenameDialog({ tenant, onClose, onSaved }: { tenant: Tenant; onClose: () => void; onSaved: (t: Tenant) => void }) {
  const [name, setName] = useState(tenant.name);
  const save = useAction(async () => {
    const t = await api.updateTenant(tenant.id, { name: name.trim() });
    onSaved(t);
  });
  const errs = fieldErrors(save.error);
  return (
    <Dialog title={`Rename ${tenant.name}`} onClose={onClose}>
      <form
        class="stack"
        onSubmit={(e) => {
          e.preventDefault();
          void save.run();
        }}
        noValidate
      >
        <TextField label="Name" value={name} onInput={setName} error={errs.name} maxLength={80} />
        {save.error !== undefined && !errs.name && <ErrorNotice error={save.error} />}
        <div class="row end">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.busy} disabled={!name.trim() || name.trim() === tenant.name}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export default function Tenants(_props: Record<string, unknown>) {
  useDocumentTitle('Tenants');
  const { setTenantId, tenantId, refreshTenants } = useApp();
  const list = useApi(() => api.tenants(), []);
  const [toggle, setToggle] = useState<Tenant | null>(null);
  const [rename, setRename] = useState<Tenant | null>(null);
  const [message, setMessage] = useState('');

  const changeStatus = useAction(async (t: Tenant) => {
    const next = t.status === 'active' ? 'suspended' : 'active';
    await api.updateTenant(t.id, { status: next });
    setMessage(`${t.name} is now ${next}.`);
    setToggle(null);
    list.reload();
    void refreshTenants().catch(() => {});
  });

  const tenants = list.data ?? [];
  return (
    <>
      <PageHeader title="Tenants" subtitle="Each tenant has its own domains, keys, webhooks and suppressions. Use the picker in the header to act on one." />
      {message && (
        <Notice tone="ok">
          <span role="status">{message}</span>
        </Notice>
      )}
      {list.loading && !list.data && <Loading />}
      {list.error !== undefined && <ErrorNotice error={list.error} onRetry={list.reload} />}
      {list.data && (
        <Card title="All tenants">
          {tenants.length === 0 ? (
            <EmptyState title="No tenants yet">Create the first tenant below.</EmptyState>
          ) : (
            <div class="table-wrap">
              <table>
                <caption class="sr-only">Tenants</caption>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Id</th>
                    <th scope="col">Status</th>
                    <th scope="col">Created</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tenants.map((t) => (
                    <tr key={t.id}>
                      <th scope="row">
                        {t.name} {t.id === tenantId && <span class="muted small">(selected)</span>}
                      </th>
                      <td>
                        <code>{t.id}</code>
                      </td>
                      <td>
                        <StatusChip status={t.status === 'suspended' ? 'deferred' : t.status} label={t.status} />
                      </td>
                      <td>{formatDateTime(t.createdAt)}</td>
                      <td>
                        <div class="row">
                          <Button class="btn-small" onClick={() => setTenantId(t.id)} disabled={t.id === tenantId} aria-label={`Act on ${t.name}`}>
                            Act on
                          </Button>
                          <Button class="btn-small" onClick={() => setRename(t)} aria-label={`Rename ${t.name}`}>
                            Rename
                          </Button>
                          <Button class="btn-small" variant={t.status === 'active' ? 'danger' : 'default'} onClick={() => setToggle(t)} aria-label={`${t.status === 'active' ? 'Suspend' : 'Activate'} ${t.name}`}>
                            {t.status === 'active' ? 'Suspend' : 'Activate'}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      <CreateTenant
        onCreated={(t) => {
          setMessage(`Tenant ${t.name} created.`);
          list.reload();
          // The first tenant of a fresh install becomes the one acted on; later ones are only added to the picker.
          void refreshTenants(tenantId ? undefined : t.id).catch(() => {});
        }}
      />

      {toggle && (
        <ConfirmDialog
          title={toggle.status === 'active' ? `Suspend ${toggle.name}?` : `Activate ${toggle.name}?`}
          confirmLabel={toggle.status === 'active' ? 'Suspend' : 'Activate'}
          danger={toggle.status === 'active'}
          busy={changeStatus.busy}
          error={changeStatus.error}
          onCancel={() => {
            setToggle(null);
            changeStatus.clearError();
          }}
          onConfirm={() => void changeStatus.run(toggle)}
        >
          <p>
            {toggle.status === 'active'
              ? 'A suspended tenant cannot send mail or use its API keys. Its data is kept and you can activate it again.'
              : 'The tenant can send mail and use its API keys again.'}
          </p>
        </ConfirmDialog>
      )}
      {rename && (
        <RenameDialog
          tenant={rename}
          onClose={() => setRename(null)}
          onSaved={(t) => {
            setRename(null);
            setMessage(`Renamed to ${t.name}.`);
            list.reload();
            void refreshTenants().catch(() => {});
          }}
        />
      )}
    </>
  );
}
