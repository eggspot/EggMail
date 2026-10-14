import { useState } from 'preact/hooks';
import { api } from '../../api/endpoints';
import { fieldErrors } from '../../api/errorMessages';
import type { TlsPolicy, TlsPolicyLevel } from '../../api/types';
import { Button, Card, Chip, ConfirmDialog, Dialog, EmptyState, ErrorNotice, Field, Loading, Notice, PageHeader, TextField } from '../../components/ui';
import { useAction, useApi, useDocumentTitle } from '../../lib/hooks';

export const TLS_LEVELS: { value: TlsPolicyLevel; label: string; hint: string }[] = [
  { value: 'may', label: 'may: TLS when offered, any certificate (the default)', hint: 'STARTTLS when the server offers it, plaintext otherwise. An MTA-STS or DANE policy of the destination can only make this stricter.' },
  { value: 'encrypt', label: 'encrypt: TLS required, certificate not checked', hint: 'Mail is deferred (and finally bounces) when the server cannot do TLS. MTA-STS and DANE still apply on top.' },
  { value: 'verify', label: 'verify: TLS required, certificate checked', hint: 'The certificate must be valid for the mail server host name. MTA-STS and DANE still apply on top.' },
  { value: 'none', label: 'none: never use TLS', hint: 'Mail goes in plaintext and MTA-STS and DANE are not consulted, even where the destination publishes an enforcing policy.' },
];

const levelTone = (l: TlsPolicyLevel) => (l === 'none' ? 'bad' : l === 'may' ? 'neutral' : 'ok');

function PolicyForm({ policy, onSaved, onCancel, submitLabel }: { policy?: TlsPolicy; onSaved: (p: TlsPolicy) => void; onCancel?: () => void; submitLabel: string }) {
  const [pattern, setPattern] = useState(policy?.domainPattern ?? '');
  const [level, setLevel] = useState<TlsPolicyLevel>(policy?.level ?? 'verify');
  const [acknowledged, setAcknowledged] = useState(false);
  const catchAllOff = pattern.trim() === '*' && level === 'none';
  const save = useAction(async () => {
    const body = { domainPattern: pattern.trim(), level, ...(catchAllOff ? { acknowledgeInsecure: true } : {}) };
    return policy ? api.updateTlsPolicy(policy.id, body) : api.createTlsPolicy(body);
  });
  const errs = fieldErrors(save.error);
  const explained = !!errs.domainPattern || !!errs.level || !!errs.acknowledgeInsecure;
  const chosen = TLS_LEVELS.find((l) => l.value === level);
  return (
    <form
      class="stack"
      noValidate
      onSubmit={async (e) => {
        e.preventDefault();
        const saved = await save.run();
        if (saved) {
          onSaved(saved);
          if (!policy) setPattern('');
        }
      }}
    >
      <div class="form-grid">
        <TextField
          label="Recipient domain"
          value={pattern}
          onInput={setPattern}
          error={errs.domainPattern}
          placeholder="example.com, *.example.com or *"
          hint="A domain name, *.suffix for every subdomain at any depth (add the domain itself separately to cover it), or * for every destination. The most specific pattern wins."
          autocomplete="off"
          spellcheck={false}
        />
        <Field label="TLS level" error={errs.level} hint={chosen?.hint}>
          {({ id, describedBy, invalid }) => (
            <select id={id} value={level} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => setLevel((e.currentTarget as HTMLSelectElement).value as TlsPolicyLevel)}>
              {TLS_LEVELS.map((l) => (
                <option key={l.value} value={l.value}>
                  {l.label}
                </option>
              ))}
            </select>
          )}
        </Field>
      </div>
      {level === 'none' && <Notice tone="warn">Level none turns TLS off for these destinations. MTA-STS and DANE are not consulted for them.</Notice>}
      {catchAllOff && (
        <div class="stack">
          <Notice tone="bad" title="This turns TLS off for every destination">
            <p>Mail would go in plaintext everywhere, including to servers that publish an enforcing MTA-STS or DANE policy.</p>
          </Notice>
          <div class="check">
            <input id={`ack-${policy?.id ?? 'new'}`} type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged((e.currentTarget as HTMLInputElement).checked)} />
            <label for={`ack-${policy?.id ?? 'new'}`}>I understand that all mail will be sent without TLS and without MTA-STS or DANE</label>
          </div>
          {errs.acknowledgeInsecure && <div class="error-text">{errs.acknowledgeInsecure}</div>}
        </div>
      )}
      {pattern.trim() === '*' && (level === 'verify' || level === 'encrypt') && (
        <Notice tone="warn">This applies to every destination: mail to servers without {level === 'verify' ? 'a valid certificate or ' : ''}STARTTLS is deferred and finally bounces.</Notice>
      )}
      {save.error !== undefined && !explained && <ErrorNotice error={save.error} />}
      <div class="row end">
        {onCancel && <Button onClick={onCancel}>Cancel</Button>}
        <Button type="submit" variant="primary" busy={save.busy} disabled={!pattern.trim() || (catchAllOff && !acknowledged)}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}

export default function TlsPolicies(_props: Record<string, unknown>) {
  useDocumentTitle('TLS policies');
  const list = useApi(() => api.tlsPolicies(), []);
  const [editing, setEditing] = useState<TlsPolicy | null>(null);
  const [deleting, setDeleting] = useState<TlsPolicy | null>(null);
  const [message, setMessage] = useState('');
  const del = useAction(async (p: TlsPolicy) => {
    await api.deleteTlsPolicy(p.id);
    setMessage(`Policy for ${p.domainPattern} deleted.`);
    setDeleting(null);
    list.reload();
  });

  const policies = list.data ?? [];
  return (
    <>
      <PageHeader
        title="TLS policies"
        subtitle="How outgoing mail uses TLS, per recipient domain. Without a policy a destination gets the default: TLS when offered, plaintext otherwise, with MTA-STS and DANE applied where the destination publishes them."
      />
      {message && (
        <Notice tone="ok">
          <span role="status">{message}</span>
        </Notice>
      )}
      {list.loading && !list.data && <Loading />}
      {list.error !== undefined && <ErrorNotice error={list.error} onRetry={list.reload} />}
      {list.data && (
        <Card title="Policies">
          {policies.length === 0 ? (
            <EmptyState title="No policies">Every destination uses the default.</EmptyState>
          ) : (
            <div class="table-wrap">
              <table>
                <caption class="sr-only">TLS policies</caption>
                <thead>
                  <tr>
                    <th scope="col">Recipient domain</th>
                    <th scope="col">Level</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.map((p) => (
                    <tr key={p.id}>
                      <th scope="row">
                        <code>{p.domainPattern}</code>
                      </th>
                      <td>
                        <Chip tone={levelTone(p.level)}>{p.level}</Chip>
                        {p.warnings.map((w) => (
                          <div key={w} class="muted small">
                            {w}
                          </div>
                        ))}
                      </td>
                      <td>
                        <div class="row">
                          <Button class="btn-small" onClick={() => setEditing(p)} aria-label={`Edit ${p.domainPattern}`}>
                            Edit
                          </Button>
                          <Button class="btn-small" variant="danger" onClick={() => setDeleting(p)} aria-label={`Delete ${p.domainPattern}`}>
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

      <Card title="Add a policy">
        <PolicyForm
          submitLabel="Add policy"
          onSaved={(p) => {
            setMessage(`Policy for ${p.domainPattern} added.`);
            list.reload();
          }}
        />
      </Card>

      <Card title="How a policy combines with MTA-STS and DANE">
        <ul class="stack">
          <li>A destination with usable DANE (TLSA records, DNSSEC validated by your resolver) always gets DANE, whatever its level. MTA-STS is ignored for it, and a broken DANE setup is never overridden.</li>
          <li>Otherwise a destination with an MTA-STS policy in enforce mode needs TLS and a valid certificate, whatever its level; in testing mode the level is the floor.</li>
          <li>The level decides everything else. Only <code>none</code> can make a destination weaker than what it publishes, because it switches the lookups off.</li>
          <li>The most specific pattern wins: an exact domain, then the longest <code>*.suffix</code>, then <code>*</code>. <code>*.example.com</code> covers every subdomain at any depth but not <code>example.com</code> itself; add a policy for it too.</li>
          <li>A policy applies to direct delivery. Mail that goes through a relay route is only as protected as the connection to the relay and the relay's own onward delivery.</li>
        </ul>
        <p class="muted small">Changes reach the delivery engine of this server at once and other servers within 30 seconds. They apply to the next delivery attempt, including retries of mail already queued.</p>
      </Card>

      {editing && (
        <Dialog title={`Edit ${editing.domainPattern}`} onClose={() => setEditing(null)}>
          <PolicyForm
            policy={editing}
            submitLabel="Save"
            onCancel={() => setEditing(null)}
            onSaved={(p) => {
              setEditing(null);
              setMessage(`Policy for ${p.domainPattern} saved.`);
              list.reload();
            }}
          />
        </Dialog>
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete the policy for ${deleting.domainPattern}?`}
          confirmLabel="Delete policy"
          busy={del.busy}
          error={del.error}
          onCancel={() => {
            setDeleting(null);
            del.clearError();
          }}
          onConfirm={() => void del.run(deleting)}
        >
          <p>Matching destinations fall back to the next less specific pattern, or to the default.</p>
        </ConfirmDialog>
      )}
    </>
  );
}
