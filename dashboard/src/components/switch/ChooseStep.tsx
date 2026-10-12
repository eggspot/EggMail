import { useState } from 'preact/hooks';
import { ErrorNotice, Field, Button, Notice, TextField } from '../ui';
import { backendLabel, normalizeForm, QUIESCE_TIMEOUT_SECONDS, validateForm, validatePassphrase, PASSPHRASE_MIN_LENGTH } from '../../lib/switchFlow';
import type { SwitchForm } from '../../lib/switchFlow';

export interface Secrets {
  passphrase: string;
  repeat: string;
}

interface Props {
  currentBackend: string;
  form: SwitchForm;
  onForm: (f: SwitchForm) => void;
  secrets: Secrets;
  onSecrets: (s: Secrets) => void;
  busy: boolean;
  error: unknown;
  onPreflight: () => void;
}

/** Step 1: direction, drain or quiesce, what to include, the target, and the export passphrase. */
export function ChooseStep({ currentBackend, form, onForm, secrets, onSecrets, busy, error, onPreflight }: Props) {
  const [tried, setTried] = useState(false);
  const set = (patch: Partial<SwitchForm>) => onForm(normalizeForm({ ...form, ...patch }));
  const formErrors = validateForm(form);
  const passErrors = validatePassphrase(secrets.passphrase, secrets.repeat);
  const valid = Object.keys(formErrors).length === 0 && !passErrors.passphrase && !passErrors.repeat;
  const show = (e?: string) => (tried ? e : undefined);

  const submit = (e: Event) => {
    e.preventDefault();
    setTried(true);
    if (valid) onPreflight();
  };

  return (
    <form class="stack" onSubmit={submit} noValidate aria-label="Choose the switch">
      <p>
        The server currently stores its data in <strong>{backendLabel(currentBackend)}</strong>. Switching only changes where data is stored: every feature and setting stays as it
        is. Nothing happens until you press the buttons in this guide, and you can roll back until you activate.
      </p>

      <p data-testid="direction">
        <strong>Direction:</strong> {backendLabel(currentBackend)} to {backendLabel(form.to)}. Switching works the same in both directions.
      </p>

      <fieldset>
        <legend>How to stop the source</legend>
        <div class="check">
          <input type="radio" id="sw-mode-drain" name="sw-mode" checked={form.mode === 'drain'} onChange={() => set({ mode: 'drain' })} />
          <label for="sw-mode-drain">
            <strong>Drain (safe default).</strong> Stop accepting mail and wait for the queue to empty. Nothing queued has to move, so there is nothing to duplicate. You can wait, cancel and resume, or let messages expire.
          </label>
        </div>
        <div class="check">
          <input type="radio" id="sw-mode-quiesce" name="sw-mode" checked={form.mode === 'quiesce'} onChange={() => set({ mode: 'quiesce' })} />
          <label for="sw-mode-quiesce">
            <strong>Quiesce.</strong> Do not wait for an empty queue. The server stops accepting mail (SMTP 421, API 503 with Retry-After), lets in-flight deliveries finish for up to {QUIESCE_TIMEOUT_SECONDS} seconds
            (<code>Switch:QuiesceTimeoutSeconds</code>), then requeues what is left with the same message id and retry state, and moves it to the target. Delivery stays at-least-once: a delivery cut off
            after the message data was sent is flagged <code>possible_duplicate</code>.
          </label>
        </div>
      </fieldset>

      <fieldset>
        <legend>What to include</legend>
        <p class="hint">Configuration, certificates, suppressions, webhook endpoints and statistics always move.</p>
        <div class="check">
          <input type="checkbox" id="sw-inc-queue" checked={form.includeQueue} disabled={form.mode === 'drain'} onChange={(e) => set({ includeQueue: (e.currentTarget as HTMLInputElement).checked })} />
          <label for="sw-inc-queue">
            Queued mail {form.mode === 'drain' ? '(only with quiesce; a drain empties the queue first)' : '(transferred with bodies and retry state)'}
          </label>
        </div>
        <div class="check">
          <input type="checkbox" id="sw-inc-history" checked={form.includeHistory} onChange={(e) => set({ includeHistory: (e.currentTarget as HTMLInputElement).checked })} />
          <label for="sw-inc-history">Per-message history (events, content, retained raw)</label>
        </div>
        {form.includeHistory && (
          <Notice tone="warn" title="History can be large">
            History is proportional to retained bytes (a modeled example is about 14 GB for 7 days of content, and more with attachments). Copy time has not been measured, so any estimate is unverified. You can skip it
            now, or copy it after activation. If the target stores no per-message history (<code>History:Mode=StatsOnly</code>) it is not carried over and stays in the read-only source.
          </Notice>
        )}
      </fieldset>

      <fieldset>
        <legend>Target ({backendLabel(form.to)})</legend>
        {form.to === 'postgres' ? (
          <div class="form-grid">
            <TextField label="Connection name" value={form.connectionName} onInput={(v) => set({ connectionName: v })} hint="A named connection from your deployment configuration. Passwords are referenced by name and never typed here." />
            <TextField label="Host" value={form.host} onInput={(v) => set({ host: v })} error={show(formErrors.host)} disabled={!!form.connectionName.trim()} />
            <TextField label="Port" value={form.port} onInput={(v) => set({ port: v })} error={show(formErrors.port)} inputMode="numeric" disabled={!!form.connectionName.trim()} />
            <TextField label="Database" value={form.database} onInput={(v) => set({ database: v })} error={show(formErrors.database)} disabled={!!form.connectionName.trim()} />
          </div>
        ) : (
          <TextField label="Data directory" value={form.path} onInput={(v) => set({ path: v })} error={show(formErrors.path)} hint="A local volume only; SQLite WAL does not work on network filesystems." />
        )}
      </fieldset>

      <fieldset>
        <legend>Export passphrase</legend>
        <p class="hint">
          The bundle protects secrets (DKIM keys, webhook secrets, certificate keys) with ASP.NET Core Data Protection, using a throwaway certificate locked by this passphrase. Nothing is written in clear. The
          passphrase is kept in this page only until the switch starts, is never stored, and must be shared with the target out of band. Minimum {PASSPHRASE_MIN_LENGTH} characters.
        </p>
        <div class="form-grid">
          <TextField label="Passphrase" type="password" autocomplete="new-password" value={secrets.passphrase} onInput={(v) => onSecrets({ ...secrets, passphrase: v })} error={show(passErrors.passphrase)} />
          <Field label="Repeat passphrase" error={show(passErrors.repeat)}>
            {({ id, describedBy, invalid }) => (
              <input id={id} type="password" autocomplete="new-password" value={secrets.repeat} aria-describedby={describedBy} aria-invalid={invalid || undefined} onInput={(e) => onSecrets({ ...secrets, repeat: (e.currentTarget as HTMLInputElement).value })} />
            )}
          </Field>
        </div>
      </fieldset>

      {error !== undefined && error !== null && <ErrorNotice error={error} title="Preflight could not run" />}
      <div class="row">
        <Button type="submit" variant="primary" busy={busy}>
          {busy ? 'Checking...' : 'Run preflight checks'}
        </Button>
        <span class="muted small">Preflight only reads; it changes nothing.</span>
      </div>
    </form>
  );
}
