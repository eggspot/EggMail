import type { SwitchStatus } from '../../api/types';
import { backendLabel } from '../../lib/switchFlow';
import { Button, CopyButton, ErrorNotice, Notice } from '../ui';
import { RollbackControl } from './RunningSteps';

/** Step 6: activate. Shows the cutover patch for orchestrator-managed deployments. */
export function ActivateStep({ status, onActivate, onRollback, busy, error }: { status: SwitchStatus; onActivate: () => void; onRollback: () => Promise<unknown>; busy: boolean; error: unknown }) {
  const patch = status.orchestratorManaged ? status.cutoverPatch : null;
  return (
    <div class="stack">
      {status.orchestratorManaged ? (
        <>
          <Notice tone="info" title="Orchestrator-managed deployment">
            EggMail never rewrites environment variables, ConfigMaps or compose files. Apply the patch below to your deployment and restart it. On start, the application finds the confirmed switch in the target, atomically
            moves it to active and only then starts accepting and sending mail. A forgotten replica still pointed at the old store is fenced and refuses to send.
          </Notice>
          {patch ? (
            <div>
              <div class="row between">
                <strong>Cutover patch ({patch.kind})</strong>
                <CopyButton text={patch.text} what="cutover patch" />
              </div>
              <pre class="patch" data-testid="cutover-patch">
                {patch.text}
              </pre>
              <p class="muted small">Secrets are referenced by name and never printed here.</p>
            </div>
          ) : (
            <Notice tone="warn">The server has not produced a cutover patch yet. Reload in a moment.</Notice>
          )}
        </>
      ) : (
        <Notice tone="info" title="Bootstrap-file deployment">
          Activating writes the new storage pointer into the bootstrap file on the data volume and restarts the server. The target then starts accepting and sending mail.
        </Notice>
      )}
      {error !== undefined && error !== null && <ErrorNotice error={error} />}
      <div class="row">
        <Button variant="primary" onClick={onActivate} busy={busy}>
          Activate the target
        </Button>
        <RollbackControl onRollback={onRollback} busy={busy} error={error} />
      </div>
    </div>
  );
}

/** Step 7: finalize. Rollback is no longer offered; going back means running the flow in reverse. */
export function FinalizeStep({ status, onFinalize, busy, error }: { status: SwitchStatus; onFinalize: () => void; busy: boolean; error: unknown }) {
  const toName = backendLabel(status.direction?.to ?? 'the target');
  const fromName = backendLabel(status.direction?.from ?? 'the source');
  return (
    <div class="stack">
      <Notice tone="ok" title={`${toName} is live`}>
        The target now accepts and sends mail. The source ({fromName}) is fenced and read-only.
      </Notice>
      <Notice tone="warn" title="Rollback is no longer available">
        After activation the target may already have delivered mail, so un-fencing the source is refused. To go back, run this same flow in reverse ({toName} to {fromName}); it fences the target and transfers
        what is still queued.
      </Notice>
      <p>
        Finalizing is a separate, explicit step. <strong>EggMail never deletes the source.</strong> After you finalize, remove the old data yourself when you are sure, and delete the bundle and its export
        passphrase, because the bundle is sensitive.
      </p>
      {error !== undefined && error !== null && <ErrorNotice error={error} />}
      <div class="row">
        <Button variant="primary" onClick={onFinalize} busy={busy}>
          Finalize the switch
        </Button>
      </div>
    </div>
  );
}

export function DoneStep({ status, onAgain }: { status: SwitchStatus; onAgain: () => void }) {
  return (
    <div class="stack">
      <Notice tone="ok" title="Switch finalized">
        {backendLabel(status.direction?.to ?? 'The target')} is the live store. The old store ({backendLabel(status.direction?.from ?? 'source')}) is untouched: remove it yourself when you are ready, and delete the bundle.
      </Notice>
      <div class="row">
        <Button onClick={onAgain}>Plan another switch</Button>
      </div>
    </div>
  );
}
