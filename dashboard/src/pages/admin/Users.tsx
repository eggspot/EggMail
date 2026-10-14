import { useState } from 'preact/hooks';
import { api } from '../../api/endpoints';
import { fieldErrors } from '../../api/errorMessages';
import type { DashboardUser, Role, Tenant } from '../../api/types';
import { Button, Card, Chip, ConfirmDialog, Dialog, EmptyState, ErrorNotice, Field, Loading, Notice, OneTimeSecret, PageHeader, StatusChip, TextField } from '../../components/ui';
import { formatDateTime } from '../../lib/format';
import { useAction, useApi, useDocumentTitle } from '../../lib/hooks';
import { useApp } from '../../state/app';

const MIN_PASSWORD = 10;

interface Secret {
  title: string;
  value: string;
}

function RoleAndTenant({
  role,
  tenantId,
  tenants,
  onRole,
  onTenant,
  errors,
}: {
  role: Role;
  tenantId: string;
  tenants: Tenant[];
  onRole: (r: Role) => void;
  onTenant: (t: string) => void;
  errors: Record<string, string>;
}) {
  const active = tenants.filter((t) => t.status === 'active');
  return (
    <>
      <Field label="Role" error={errors.role} hint="Administrators manage the whole server. Tenant users see one tenant only.">
        {({ id, describedBy, invalid }) => (
          <select id={id} value={role} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => onRole((e.currentTarget as HTMLSelectElement).value as Role)}>
            <option value="tenant">Tenant user</option>
            <option value="admin">Administrator</option>
          </select>
        )}
      </Field>
      {role === 'tenant' && (
        <Field label="Tenant" error={errors.tenantId}>
          {({ id, describedBy, invalid }) => (
            <select id={id} value={tenantId} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => onTenant((e.currentTarget as HTMLSelectElement).value)}>
              <option value="">Choose a tenant</option>
              {active.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          )}
        </Field>
      )}
    </>
  );
}

function CreateUser({ tenants, onCreated }: { tenants: Tenant[]; onCreated: (u: DashboardUser) => void }) {
  const [userName, setUserName] = useState('');
  const [role, setRole] = useState<Role>('tenant');
  const [tenantId, setTenantId] = useState('');
  const [password, setPassword] = useState('');
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  const create = useAction(async () =>
    api.createUser({ userName: userName.trim(), role, ...(role === 'tenant' ? { tenantId } : {}), ...(password ? { password } : {}) }),
  );
  const serverErrors = fieldErrors(create.error);
  const errs = { ...serverErrors, ...clientErrors };

  const submit = async (e: Event) => {
    e.preventDefault();
    const found: Record<string, string> = {};
    if (!userName.trim()) found.userName = 'Enter a user name.';
    if (role === 'tenant' && !tenantId) found.tenantId = 'Choose the tenant this user belongs to.';
    if (password && password.length < MIN_PASSWORD) found.password = `Use at least ${MIN_PASSWORD} characters, or leave it empty to have one generated.`;
    setClientErrors(found);
    if (Object.keys(found).length) return;
    const created = await create.run();
    if (created) {
      setUserName('');
      setPassword('');
      onCreated(created);
    }
  };

  return (
    <Card title="Create a user">
      <form class="form-grid" onSubmit={submit} noValidate>
        <TextField label="User name" value={userName} onInput={setUserName} error={errs.userName} autocomplete="off" maxLength={256} hint="Sign-in name. Not case sensitive." />
        <RoleAndTenant role={role} tenantId={tenantId} tenants={tenants} onRole={setRole} onTenant={setTenantId} errors={errs} />
        <TextField
          label="Password (optional)"
          type="password"
          value={password}
          onInput={setPassword}
          error={errs.password}
          autocomplete="new-password"
          hint={`Leave empty to generate one; it is shown once. At least ${MIN_PASSWORD} characters.`}
        />
        <div>
          <Button type="submit" variant="primary" busy={create.busy}>
            Create user
          </Button>
        </div>
      </form>
      {create.error !== undefined && Object.keys(serverErrors).every((f) => !['userName', 'role', 'tenantId', 'password'].includes(f)) && <ErrorNotice error={create.error} />}
    </Card>
  );
}

function EditDialog({ user, tenants, onClose, onSaved }: { user: DashboardUser; tenants: Tenant[]; onClose: () => void; onSaved: (u: DashboardUser) => void }) {
  const [role, setRole] = useState<Role>(user.role);
  const [tenantId, setTenantId] = useState(user.tenantId ?? '');
  const changed = role !== user.role || (role === 'tenant' && tenantId !== (user.tenantId ?? ''));
  const save = useAction(async () => {
    const saved = await api.updateUser(user.id, { ...(role !== user.role ? { role } : {}), ...(role === 'tenant' && tenantId !== (user.tenantId ?? '') ? { tenantId } : {}) });
    onSaved(saved);
  });
  const errs = fieldErrors(save.error);
  return (
    <Dialog title={`Change role of ${user.userName}`} onClose={onClose}>
      <form
        class="stack"
        onSubmit={(e) => {
          e.preventDefault();
          void save.run();
        }}
        noValidate
      >
        <RoleAndTenant role={role} tenantId={tenantId} tenants={tenants} onRole={setRole} onTenant={setTenantId} errors={errs} />
        <p class="muted small">The user is signed out everywhere when the role or the tenant changes.</p>
        {save.error !== undefined && !errs.role && !errs.tenantId && <ErrorNotice error={save.error} />}
        <div class="row end">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.busy} disabled={!changed || (role === 'tenant' && !tenantId)}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function ResetDialog({ user, onClose, onDone }: { user: DashboardUser; onClose: () => void; onDone: (u: DashboardUser) => void }) {
  const [password, setPassword] = useState('');
  const reset = useAction(async () => onDone(await api.resetUserPassword(user.id, password || undefined)));
  const errs = fieldErrors(reset.error);
  return (
    <Dialog title={`Reset the password of ${user.userName}`} onClose={onClose}>
      <form
        class="stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (password && password.length < MIN_PASSWORD) return;
          void reset.run();
        }}
        noValidate
      >
        <p>The user is signed out everywhere and must use the new password.</p>
        <TextField
          label="New password (optional)"
          type="password"
          value={password}
          onInput={setPassword}
          error={errs.password ?? (password && password.length < MIN_PASSWORD ? `Use at least ${MIN_PASSWORD} characters.` : undefined)}
          autocomplete="new-password"
          hint="Leave empty to generate one; it is shown once."
        />
        {reset.error !== undefined && !errs.password && <ErrorNotice error={reset.error} />}
        <div class="row end">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" busy={reset.busy} disabled={!!password && password.length < MIN_PASSWORD}>
            Reset password
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export default function Users(_props: Record<string, unknown>) {
  useDocumentTitle('Users');
  const { me } = useApp();
  const list = useApi(() => api.users(), []);
  const tenantList = useApi(() => api.tenants(), []);
  const [message, setMessage] = useState('');
  const [secret, setSecret] = useState<Secret | null>(null);
  const [toggle, setToggle] = useState<DashboardUser | null>(null);
  const [edit, setEdit] = useState<DashboardUser | null>(null);
  const [reset, setReset] = useState<DashboardUser | null>(null);
  const [remove, setRemove] = useState<DashboardUser | null>(null);

  const tenants = tenantList.data ?? [];
  const tenantName = (id?: string | null) => (id ? (tenants.find((t) => t.id === id)?.name ?? id) : '');

  const changeEnabled = useAction(async (u: DashboardUser) => {
    const next = !u.enabled;
    await api.updateUser(u.id, { enabled: next });
    setMessage(next ? `${u.userName} can sign in again.` : `${u.userName} is disabled and was signed out everywhere.`);
    setToggle(null);
    list.reload();
  });
  const doDelete = useAction(async (u: DashboardUser) => {
    await api.deleteUser(u.id);
    setMessage(`${u.userName} was deleted.`);
    setRemove(null);
    list.reload();
  });

  const users = list.data ?? [];
  return (
    <>
      <PageHeader title="Users" subtitle="People who sign in to this dashboard. Changes apply at once; a disabled or reset user is signed out everywhere." />
      {message && (
        <Notice tone="ok">
          <span role="status">{message}</span>
        </Notice>
      )}
      {secret && <OneTimeSecret title={secret.title} secret={secret.value} hint="Give it to the user over a safe channel. Only a hash is stored on the server." onDone={() => setSecret(null)} />}
      {list.loading && !list.data && <Loading />}
      {list.error !== undefined && <ErrorNotice error={list.error} onRetry={list.reload} />}
      {list.data && (
        <Card title="All users">
          {users.length === 0 ? (
            <EmptyState title="No users">Create the first user below.</EmptyState>
          ) : (
            <div class="table-wrap">
              <table>
                <caption class="sr-only">Dashboard users</caption>
                <thead>
                  <tr>
                    <th scope="col">User</th>
                    <th scope="col">Role</th>
                    <th scope="col">Tenant</th>
                    <th scope="col">Status</th>
                    <th scope="col">Created</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <th scope="row">
                        {u.userName} {u.userName === me?.user && <span class="muted small">(you)</span>}
                      </th>
                      <td>
                        <Chip tone={u.role === 'admin' ? 'info' : 'neutral'}>{u.role === 'admin' ? 'administrator' : 'tenant user'}</Chip>
                      </td>
                      <td>{u.role === 'tenant' ? tenantName(u.tenantId) : <span class="muted">All tenants</span>}</td>
                      <td>
                        <StatusChip status={u.enabled ? 'active' : 'deferred'} label={u.enabled ? 'enabled' : 'disabled'} />
                      </td>
                      <td>{formatDateTime(u.createdAt)}</td>
                      <td>
                        <div class="row">
                          <Button class="btn-small" onClick={() => setEdit(u)} aria-label={`Change role of ${u.userName}`}>
                            Role
                          </Button>
                          <Button class="btn-small" onClick={() => setReset(u)} disabled={u.userName === me?.user} aria-label={`Reset password of ${u.userName}`}>
                            Reset password
                          </Button>
                          <Button class="btn-small" variant={u.enabled ? 'danger' : 'default'} onClick={() => setToggle(u)} aria-label={`${u.enabled ? 'Disable' : 'Enable'} ${u.userName}`}>
                            {u.enabled ? 'Disable' : 'Enable'}
                          </Button>
                          <Button class="btn-small" variant="danger" onClick={() => setRemove(u)} aria-label={`Delete ${u.userName}`}>
                            Delete
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

      <CreateUser
        tenants={tenants}
        onCreated={(u) => {
          setMessage(`User ${u.userName} created.`);
          setSecret(u.password ? { title: `Password for "${u.userName}"`, value: u.password } : null);
          list.reload();
        }}
      />

      {toggle && (
        <ConfirmDialog
          title={toggle.enabled ? `Disable ${toggle.userName}?` : `Enable ${toggle.userName}?`}
          confirmLabel={toggle.enabled ? 'Disable' : 'Enable'}
          danger={toggle.enabled}
          busy={changeEnabled.busy}
          error={changeEnabled.error}
          onCancel={() => {
            setToggle(null);
            changeEnabled.clearError();
          }}
          onConfirm={() => void changeEnabled.run(toggle)}
        >
          <p>
            {toggle.enabled
              ? 'The user is signed out everywhere and cannot sign in until you enable the account again. The last enabled administrator cannot be disabled.'
              : 'The user can sign in again with the current password.'}
          </p>
        </ConfirmDialog>
      )}
      {remove && (
        <ConfirmDialog
          title={`Delete ${remove.userName}?`}
          confirmLabel="Delete user"
          busy={doDelete.busy}
          error={doDelete.error}
          onCancel={() => {
            setRemove(null);
            doDelete.clearError();
          }}
          onConfirm={() => void doDelete.run(remove)}
        >
          <p>The account and its sessions are removed. This cannot be undone. The last enabled administrator cannot be deleted.</p>
        </ConfirmDialog>
      )}
      {edit && (
        <EditDialog
          user={edit}
          tenants={tenants}
          onClose={() => setEdit(null)}
          onSaved={(u) => {
            setEdit(null);
            setMessage(`${u.userName} is now ${u.role === 'admin' ? 'an administrator' : `a user of ${tenantName(u.tenantId)}`}.`);
            list.reload();
          }}
        />
      )}
      {reset && (
        <ResetDialog
          user={reset}
          onClose={() => setReset(null)}
          onDone={(u) => {
            setReset(null);
            setMessage(`The password of ${u.userName} was reset and the user was signed out everywhere.`);
            setSecret(u.password ? { title: `New password for "${u.userName}"`, value: u.password } : null);
            list.reload();
          }}
        />
      )}
    </>
  );
}
