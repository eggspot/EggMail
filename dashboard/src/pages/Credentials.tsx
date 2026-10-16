import { useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { fieldErrors } from '../api/errorMessages';
import { API_KEY_SCOPES } from '../api/types';
import type { ApiKey, SmtpCredential } from '../api/types';
import { CheckboxGroup } from '../components/CheckboxGroup';
import { Button, Card, Chip, ConfirmDialog, EmptyState, ErrorNotice, Loading, OneTimeSecret, PageHeader, TextField } from '../components/ui';
import { formatDateTime, formatRelative } from '../lib/format';
import { useAction, useApi, useDocumentTitle } from '../lib/hooks';

const SCOPE_HELP: Record<string, string> = {
  send: 'send mail',
  read: 'read messages and statistics',
  domains: 'manage domains',
  webhooks: 'manage webhooks',
  suppressions: 'manage suppressions',
  keys: 'manage API keys and SMTP credentials',
  'inbound:read': 'read received mail, its settings and routes',
  'inbound:write': 'change inbound settings and routes, delete and retry received mail',
};

function ApiKeysCard({ onSecret }: { onSecret: (title: string, value: string, hint: string) => void }) {
  const { data, error, loading, reload } = useApi(() => api.apiKeys(), []);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<string[]>(['send']);
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  const [toRevoke, setToRevoke] = useState<ApiKey | null>(null);

  const create = useAction(async () => api.createApiKey(name.trim(), scopes));
  const revoke = useAction(async (id: string) => {
    await api.revokeApiKey(id);
    return true;
  });
  const serverErrors = fieldErrors(create.error);

  const submit = async (e: Event) => {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (!name.trim()) errs.name = 'Give the key a name so you can recognize it later.';
    if (scopes.length === 0) errs.scopes = 'Select at least one scope.';
    setClientErrors(errs);
    if (Object.keys(errs).length) return;
    const created = await create.run();
    if (created) {
      if (created.key) onSecret(`API key "${created.name}"`, created.key, 'Send it as Authorization: Bearer <key>. Only a SHA-256 digest is stored on the server.');
      setName('');
      reload();
    }
  };

  return (
    <Card title="API keys">
      <div class="stack">
        <form class="stack" onSubmit={submit} noValidate>
          <TextField label="Key name" value={name} onInput={setName} error={clientErrors.name ?? serverErrors.name} autocomplete="off" placeholder="Production sender" />
          <CheckboxGroup
            legend="Scopes"
            options={API_KEY_SCOPES}
            selected={scopes}
            onChange={setScopes}
            error={clientErrors.scopes ?? serverErrors.scopes}
            hint="Grant only what the integration needs (least privilege)."
            describe={(s) => SCOPE_HELP[s]}
          />
          {create.error !== undefined && !serverErrors.name && !serverErrors.scopes && <ErrorNotice error={create.error} />}
          <div>
            <Button type="submit" variant="primary" busy={create.busy}>
              Create API key
            </Button>
          </div>
        </form>
        {loading && !data && <Loading />}
        {error !== undefined && <ErrorNotice error={error} onRetry={reload} />}
        {data && data.length === 0 && (
          <EmptyState title="No API keys">
            <p>Create a key above to send mail over the HTTP API.</p>
          </EmptyState>
        )}
        {data && data.length > 0 && (
          <div class="table-wrap">
            <table>
              <caption class="sr-only">API keys</caption>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Key prefix</th>
                  <th scope="col">Scopes</th>
                  <th scope="col">Created</th>
                  <th scope="col">Last used</th>
                  <th scope="col">
                    <span class="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.map((k) => (
                  <tr key={k.id}>
                    <td>{k.name}</td>
                    <td>
                      <code>{k.prefix ?? '-'}</code>
                    </td>
                    <td>
                      <span class="row">
                        {k.scopes.map((s) => (
                          <Chip key={s} tone="info">
                            {s}
                          </Chip>
                        ))}
                      </span>
                    </td>
                    <td>{formatDateTime(k.createdAt)}</td>
                    <td>{k.lastUsedAt ? formatRelative(k.lastUsedAt) : 'Never'}</td>
                    <td>
                      <Button variant="danger" class="btn-small" onClick={() => setToRevoke(k)} aria-label={`Revoke API key ${k.name}`}>
                        Revoke
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {toRevoke && (
        <ConfirmDialog
          title={`Revoke "${toRevoke.name}"?`}
          confirmLabel="Revoke key"
          busy={revoke.busy}
          error={revoke.error}
          onCancel={() => {
            revoke.clearError();
            setToRevoke(null);
          }}
          onConfirm={async () => {
            if (await revoke.run(toRevoke.id)) {
              setToRevoke(null);
              reload();
            }
          }}
        >
          <p>Anything using this key stops working immediately. This cannot be undone.</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function SmtpCredentialsCard({ onSecret }: { onSecret: (title: string, value: string, hint: string) => void }) {
  const { data, error, loading, reload } = useApi(() => api.smtpCredentials(), []);
  const [username, setUsername] = useState('');
  const [clientError, setClientError] = useState<string | undefined>();
  const [toRevoke, setToRevoke] = useState<SmtpCredential | null>(null);

  const create = useAction(async () => api.createSmtpCredential(username.trim()));
  const revoke = useAction(async (id: string) => {
    await api.revokeSmtpCredential(id);
    return true;
  });
  const serverErrors = fieldErrors(create.error);

  const submit = async (e: Event) => {
    e.preventDefault();
    const problem = username.trim() ? undefined : 'Enter a username.';
    setClientError(problem);
    if (problem) return;
    const created = await create.run();
    if (created) {
      if (created.password)
        onSecret(`SMTP password for "${created.username}"`, created.password, 'Use it with AUTH PLAIN or LOGIN over STARTTLS or TLS only (ports 587, 465 or 2525). Passwords are stored as hashes.');
      setUsername('');
      reload();
    }
  };

  return (
    <Card title="SMTP credentials">
      <div class="stack">
        <p class="muted">Users that submit mail over SMTP (AUTH PLAIN or LOGIN, after STARTTLS or on port 465).</p>
        <form class="form-grid" onSubmit={submit} noValidate>
          <TextField label="Username" value={username} onInput={setUsername} error={clientError ?? serverErrors.username} autocomplete="off" />
          <div>
            <Button type="submit" variant="primary" busy={create.busy}>
              Create SMTP credential
            </Button>
          </div>
        </form>
        {create.error !== undefined && !serverErrors.username && <ErrorNotice error={create.error} />}
        {loading && !data && <Loading />}
        {error !== undefined && <ErrorNotice error={error} onRetry={reload} />}
        {data && data.length === 0 && (
          <EmptyState title="No SMTP credentials">
            <p>Create a username and password to submit mail over SMTP.</p>
          </EmptyState>
        )}
        {data && data.length > 0 && (
          <div class="table-wrap">
            <table>
              <caption class="sr-only">SMTP credentials</caption>
              <thead>
                <tr>
                  <th scope="col">Username</th>
                  <th scope="col">Created</th>
                  <th scope="col">
                    <span class="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.map((c) => (
                  <tr key={c.id}>
                    <td>{c.username}</td>
                    <td>{formatDateTime(c.createdAt)}</td>
                    <td>
                      <Button variant="danger" class="btn-small" onClick={() => setToRevoke(c)} aria-label={`Revoke SMTP credential ${c.username}`}>
                        Revoke
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {toRevoke && (
        <ConfirmDialog
          title={`Revoke "${toRevoke.username}"?`}
          confirmLabel="Revoke credential"
          busy={revoke.busy}
          error={revoke.error}
          onCancel={() => {
            revoke.clearError();
            setToRevoke(null);
          }}
          onConfirm={async () => {
            if (await revoke.run(toRevoke.id)) {
              setToRevoke(null);
              reload();
            }
          }}
        >
          <p>SMTP clients using this login can no longer submit mail. This cannot be undone.</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

export default function Credentials(_props: Record<string, unknown>) {
  useDocumentTitle('API keys and SMTP credentials');
  // The secret exists only here, in memory, until the user confirms they saved it.
  const [secret, setSecret] = useState<{ title: string; value: string; hint: string } | null>(null);
  const onSecret = (title: string, value: string, hint: string) => setSecret({ title, value, hint });
  return (
    <>
      <PageHeader title="API keys and SMTP credentials" subtitle="Credentials are shown once, when they are created." />
      {secret && <OneTimeSecret title={secret.title} secret={secret.value} hint={secret.hint} onDone={() => setSecret(null)} />}
      <ApiKeysCard onSecret={onSecret} />
      <SmtpCredentialsCard onSecret={onSecret} />
    </>
  );
}
