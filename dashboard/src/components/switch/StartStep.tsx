import { useState } from 'preact/hooks';
import { backendLabel, confirmationMatches, confirmationPhrase, includeList, QUIESCE_TIMEOUT_SECONDS } from '../../lib/switchFlow';
import type { SwitchForm } from '../../lib/switchFlow';
import { Button, ErrorNotice, KeyValue, Notice, TextField } from '../ui';

/** Step 3: summary and the typed confirmation that unlocks Start. Start is only ever a click on this button. */
export function StartStep({
  currentBackend,
  form,
  busy,
  error,
  onBack,
  onStart,
}: {
  currentBackend: string;
  form: SwitchForm;
  busy: boolean;
  error: unknown;
  onBack: () => void;
  onStart: (confirmation: string) => void;
}) {
  const [typed, setTyped] = useState('');
  const phrase = confirmationPhrase(form.to);
  const ok = confirmationMatches(form.to, typed);
  const include = includeList(form);
  return (
    <div class="stack">
      <KeyValue
        items={[
          ['From', backendLabel(currentBackend)],
          ['To', backendLabel(form.to)],
          ['Source handling', form.mode === 'drain' ? 'Drain (wait for an empty queue)' : `Quiesce (in-flight deliveries get up to ${QUIESCE_TIMEOUT_SECONDS} s)`],
          ['Also moves', include.length ? include.map((i) => (i === 'queue' ? 'queued mail' : 'per-message history')).join(', ') : 'only configuration, certificates and statistics'],
        ]}
      />
      <Notice tone="warn" title="What starting does">
        The source stops accepting mail (SMTP replies 421, the API replies 503 with Retry-After) and is then fenced: it keeps its data but never accepts or sends mail again until you roll back. Senders that retry
        will succeed once the target is active. <strong>Nothing is deleted.</strong> You can roll back at any point before you activate.
      </Notice>
      <TextField label={`Type "${phrase}" to confirm`} value={typed} onInput={setTyped} autocomplete="off" spellcheck={false} />
      {error !== undefined && error !== null && <ErrorNotice error={error} title="The switch could not be started" />}
      <div class="row">
        <Button onClick={onBack} disabled={busy}>
          Back
        </Button>
        <Button variant="danger" disabled={!ok} busy={busy} onClick={() => onStart(typed.trim())}>
          Start switch
        </Button>
      </div>
    </div>
  );
}
