import { useState } from 'preact/hooks';
import { api } from '../../api/endpoints';
import { fieldErrors } from '../../api/errorMessages';
import type { RelayRoute, RelayRouteCreate, RelayRoutePatch, RelayTlsMode } from '../../api/types';
import { Button, Card, Chip, ConfirmDialog, Dialog, EmptyState, ErrorNotice, Field, Loading, Notice, PageHeader, TextField } from '../../components/ui';
import { useAction, useApi, useDocumentTitle } from '../../lib/hooks';

export const RELAY_TLS_MODES: { value: RelayTlsMode; label: string; hint: string }[] = [
  { value: 'verify', label: 'verify: STARTTLS, certificate and host name checked (recommended)', hint: 'Mail is only handed over when the relay presents a valid certificate for its host name.' },
  { value: 'implicit', label: 'implicit: TLS from the first byte (port 465), certificate checked', hint: 'For relays on port 465. The certificate and host name are checked.' },
  { value: 'required', label: 'required: STARTTLS, certificate not checked', hint: 'Encrypted, but anyone in the path could impersonate the relay. Not for passwords.' },
  { value: 'starttls', label: 'starttls: STARTTLS when offered, otherwise plaintext', hint: 'Opportunistic. Not for passwords.' },
  { value: 'none', label: 'none: no TLS', hint: 'Plaintext. Credentials are refused in this mode.' },
];

/** Splits the domains field: whitespace and commas separate entries. */
export function parseDomains(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((d) => d.trim())
    .filter(Boolean);
}

interface FormState {
  name: string;
  host: string;
  port: string;
  tlsMode: RelayTlsMode;
  userName: string;
  password: string;
  removeCredentials: boolean;
  priority: string;
  enabled: boolean;
  domains: string;
}

function initial(route?: RelayRoute): FormState {
  return {
    name: route?.name ?? '',
    host: route?.host ?? '',
    port: route ? String(route.port) : '',
    tlsMode: route?.tlsMode ?? 'verify',
    userName: route?.userName ?? '',
    password: '',
    removeCredentials: false,
    priority: route ? String(route.priority) : '',
    enabled: route?.enabled ?? true,
    domains: route ? route.domains.join('\n') : '',
  };
}

/** Errors for `domains` and `domains[i]`, joined. */
function domainErrors(errs: Record<string, string>): string | undefined {
  const all = Object.entries(errs)
    .filter(([k]) => k === 'domains' || k.startsWith('domains['))
    .map(([k, v]) => {
      const index = /^domains\[(\d+)\]$/.exec(k)?.[1];
      return index === undefined ? v : `Entry ${Number(index) + 1}: ${v}`;
    });
  return all.length ? all.join(' ') : undefined;
}

function RouteForm({ route, onSaved, onCancel, submitLabel }: { route?: RelayRoute; onSaved: (r: RelayRoute) => void; onCancel?: () => void; submitLabel: string }) {
  const [f, setF] = useState<FormState>(() => initial(route));
  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => setF((prev) => ({ ...prev, [key]: value }));
  const save = useAction(async () => {
    const domains = parseDomains(f.domains);
    const port = f.port.trim() ? Number(f.port) : undefined;
    const priority = f.priority.trim() ? Number(f.priority) : undefined;
    if (route) {
      const patch: RelayRoutePatch = { name: f.name.trim(), host: f.host.trim(), tlsMode: f.tlsMode, enabled: f.enabled, domains };
      if (port !== undefined) patch.port = port;
      if (priority !== undefined) patch.priority = priority;
      if (f.removeCredentials) patch.removeCredentials = true;
      else {
        if (f.userName.trim() && f.userName.trim() !== (route.userName ?? '')) patch.userName = f.userName.trim();
        if (f.password) {
          patch.password = f.password;
          if (!patch.userName && route.userName) patch.userName = route.userName;
        }
      }
      return api.updateRelayRoute(route.id, patch);
    }
    const body: RelayRouteCreate = { name: f.name.trim(), host: f.host.trim(), tlsMode: f.tlsMode, enabled: f.enabled, domains };
    if (port !== undefined) body.port = port;
    if (priority !== undefined) body.priority = priority;
    if (f.userName.trim()) body.userName = f.userName.trim();
    if (f.password) body.password = f.password;
    return api.createRelayRoute(body);
  });
  const errs = fieldErrors(save.error);
  const known = ['name', 'host', 'port', 'tlsMode', 'userName', 'password', 'priority', 'domains', 'removeCredentials'];
  const unexplained = save.error !== undefined && !Object.keys(errs).some((k) => known.includes(k) || k.startsWith('domains['));
  const mode = RELAY_TLS_MODES.find((m) => m.value === f.tlsMode);
  const hasStoredCredentials = !!route?.userName;
  const weakWithPassword = (f.password || (hasStoredCredentials && !f.removeCredentials)) && (f.tlsMode === 'required' || f.tlsMode === 'starttls');

  return (
    <form
      class="stack"
      noValidate
      onSubmit={async (e) => {
        e.preventDefault();
        const saved = await save.run();
        if (saved) {
          onSaved(saved);
          if (!route) setF(initial());
        }
      }}
    >
      <div class="form-grid">
        <TextField label="Name" value={f.name} onInput={(v) => set('name', v)} error={errs.name} maxLength={64} hint="Shown on each delivery that used this route." autocomplete="off" />
        <TextField label="Host" value={f.host} onInput={(v) => set('host', v)} error={errs.host} placeholder="smtp.relay.example" autocomplete="off" spellcheck={false} />
        <TextField label="Port" value={f.port} onInput={(v) => set('port', v)} error={errs.port} inputMode="numeric" placeholder={f.tlsMode === 'implicit' ? '465' : '587'} autocomplete="off" />
        <Field label="TLS" error={errs.tlsMode} hint={mode?.hint}>
          {({ id, describedBy, invalid }) => (
            <select id={id} value={f.tlsMode} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => set('tlsMode', (e.currentTarget as HTMLSelectElement).value as RelayTlsMode)}>
              {RELAY_TLS_MODES.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
          )}
        </Field>
        <TextField label="Priority" value={f.priority} onInput={(v) => set('priority', v)} error={errs.priority} inputMode="numeric" placeholder="100" hint="Lower numbers are tried first, after direct delivery." autocomplete="off" />
      </div>

      <div class="form-grid">
        <TextField
          label="User name"
          value={f.userName}
          onInput={(v) => set('userName', v)}
          error={errs.userName}
          disabled={f.removeCredentials}
          autocomplete="off"
          hint="Leave empty for a relay that does not need a login."
        />
        <TextField
          label="Password"
          type="password"
          value={f.password}
          onInput={(v) => set('password', v)}
          error={errs.password}
          disabled={f.removeCredentials}
          autocomplete="new-password"
          placeholder={route?.hasPassword ? 'unchanged' : ''}
          hint={route?.hasPassword ? 'A password is stored. It is never shown; type a new one to replace it.' : 'Stored encrypted. It is never shown again.'}
        />
      </div>
      {hasStoredCredentials && (
        <div class="check">
          <input id={`rm-${route?.id}`} type="checkbox" checked={f.removeCredentials} onChange={(e) => set('removeCredentials', (e.currentTarget as HTMLInputElement).checked)} />
          <label for={`rm-${route?.id}`}>Remove the stored user name and password</label>
        </div>
      )}
      {weakWithPassword && (
        <Notice tone="warn">The relay certificate is not checked in this mode, so a password could be handed to an impostor. Use verify or implicit.</Notice>
      )}

      <Field label="Recipient domains" error={domainErrors(errs)} hint="One per line. A route is only used for the domains it lists: a name, *.suffix for a domain and everything below it, or * for every domain.">
        {({ id, describedBy, invalid }) => (
          <textarea id={id} rows={4} value={f.domains} spellcheck={false} aria-describedby={describedBy} aria-invalid={invalid || undefined} onInput={(e) => set('domains', (e.currentTarget as HTMLTextAreaElement).value)} />
        )}
      </Field>
      {f.domains.split(/[\s,]+/).includes('*') && <Notice tone="warn">* sends mail for every recipient domain through this relay whenever direct delivery cannot connect.</Notice>}

      <div class="check">
        <input id={`en-${route?.id ?? 'new'}`} type="checkbox" checked={f.enabled} onChange={(e) => set('enabled', (e.currentTarget as HTMLInputElement).checked)} />
        <label for={`en-${route?.id ?? 'new'}`}>Enabled</label>
      </div>

      {unexplained && <ErrorNotice error={save.error} />}
      <div class="row end">
        {onCancel && <Button onClick={onCancel}>Cancel</Button>}
        <Button type="submit" variant="primary" busy={save.busy} disabled={!f.name.trim() || !f.host.trim() || !f.domains.trim()}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}

export default function RelayRoutes(_props: Record<string, unknown>) {
  useDocumentTitle('Relay routes');
  const list = useApi(() => api.relayRoutes(), []);
  const [editing, setEditing] = useState<RelayRoute | null>(null);
  const [deleting, setDeleting] = useState<RelayRoute | null>(null);
  const [message, setMessage] = useState('');

  const toggle = useAction(async (r: RelayRoute) => {
    await api.updateRelayRoute(r.id, { enabled: !r.enabled });
    setMessage(`${r.name} is now ${r.enabled ? 'disabled' : 'enabled'}.`);
    list.reload();
  });
  const del = useAction(async (r: RelayRoute) => {
    await api.deleteRelayRoute(r.id);
    setMessage(`Relay route ${r.name} deleted.`);
    setDeleting(null);
    list.reload();
  });

  const routes = list.data ?? [];
  return (
    <>
      <PageHeader
        title="Relay routes"
        subtitle="Mail goes straight to the recipient's mail server on port 25. A relay is an opt-in fallback for the recipient domains it lists, for networks that block port 25. It changes the sending address of that mail (SPF, bounces)."
      />
      {message && (
        <Notice tone="ok">
          <span role="status">{message}</span>
        </Notice>
      )}
      {list.loading && !list.data && <Loading />}
      {list.error !== undefined && <ErrorNotice error={list.error} onRetry={list.reload} />}
      {toggle.error !== undefined && <ErrorNotice error={toggle.error} />}
      {list.data && (
        <Card title="Routes">
          {routes.length === 0 ? (
            <EmptyState title="No relay routes">All mail is delivered directly. Add a route below to use a relay for chosen domains.</EmptyState>
          ) : (
            <div class="table-wrap">
              <table>
                <caption class="sr-only">Relay routes</caption>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Relay</th>
                    <th scope="col">TLS</th>
                    <th scope="col">Login</th>
                    <th scope="col" class="num">
                      Priority
                    </th>
                    <th scope="col">Domains</th>
                    <th scope="col">Status</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {routes.map((r) => (
                    <tr key={r.id}>
                      <th scope="row">{r.name}</th>
                      <td>
                        <code>
                          {r.host}:{r.port}
                        </code>
                      </td>
                      <td>{r.tlsMode}</td>
                      <td>{r.userName ? `${r.userName}${r.hasPassword ? ' (password set)' : ''}` : '-'}</td>
                      <td class="num">{r.priority}</td>
                      <td>
                        <span class="row">
                          {r.domains.map((d) => (
                            <Chip key={d}>{d}</Chip>
                          ))}
                        </span>
                      </td>
                      <td>
                        <Chip tone={r.enabled ? 'ok' : 'warn'}>{r.enabled ? 'Enabled' : 'Disabled'}</Chip>
                        {r.warnings.map((w) => (
                          <div key={w} class="muted small">
                            {w}
                          </div>
                        ))}
                      </td>
                      <td>
                        <div class="row">
                          <Button class="btn-small" onClick={() => setEditing(r)} aria-label={`Edit ${r.name}`}>
                            Edit
                          </Button>
                          <Button class="btn-small" onClick={() => void toggle.run(r)} busy={toggle.busy} aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`}>
                            {r.enabled ? 'Disable' : 'Enable'}
                          </Button>
                          <Button class="btn-small" variant="danger" onClick={() => setDeleting(r)} aria-label={`Delete ${r.name}`}>
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

      <Card title="Add a relay route">
        <RouteForm
          submitLabel="Add relay route"
          onSaved={(r) => {
            setMessage(`Relay route ${r.name} added.`);
            list.reload();
          }}
        />
      </Card>

      <p class="muted small">
        Changes reach the delivery engine of this server at once and other servers within 30 seconds. They apply to the next delivery attempt, including retries of mail already queued.
      </p>

      {editing && (
        <Dialog title={`Edit ${editing.name}`} onClose={() => setEditing(null)}>
          <RouteForm
            route={editing}
            submitLabel="Save"
            onCancel={() => setEditing(null)}
            onSaved={(r) => {
              setEditing(null);
              setMessage(`Relay route ${r.name} saved.`);
              list.reload();
            }}
          />
        </Dialog>
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting.name}?`}
          confirmLabel="Delete route"
          busy={del.busy}
          error={del.error}
          onCancel={() => {
            setDeleting(null);
            del.clearError();
          }}
          onConfirm={() => void del.run(deleting)}
        >
          <p>Mail for {deleting.domains.join(', ')} is no longer offered to this relay. The stored password is deleted with the route.</p>
        </ConfirmDialog>
      )}
    </>
  );
}
