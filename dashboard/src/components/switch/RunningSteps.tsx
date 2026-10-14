import { useState } from 'preact/hooks';
import type { SwitchStatus } from '../../api/types';
import { formatNumber } from '../../lib/format';
import { stateLabel, stateText } from '../../lib/switchFlow';
import { Button, Chip, ConfirmDialog, ErrorNotice, Notice } from '../ui';

/** Rollback with an explicit confirmation dialog. Only rendered by callers while rollback is allowed. */
export function RollbackControl({ onRollback, busy, error }: { onRollback: () => Promise<unknown>; busy: boolean; error: unknown }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>
        Roll back
      </Button>
      {open && (
        <ConfirmDialog
          title="Roll back the switch?"
          confirmLabel="Roll back"
          busy={busy}
          error={error}
          onCancel={() => setOpen(false)}
          onConfirm={async () => {
            await onRollback();
            setOpen(false);
          }}
        >
          <p>
            This discards the data imported into the target, clears the transfer marks and the fence on the source, and resumes the source. Nothing was sent from the target, so no duplicates are possible.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}

/** Step 4: progress of drain or quiesce, fence, export and import. */
export function ProgressStep({ status, canRollback, onRollback, busy, error }: { status: SwitchStatus; canRollback: boolean; onRollback: () => Promise<unknown>; busy: boolean; error: unknown }) {
  const p = status.progress;
  const failed = status.state === 'failed';
  return (
    <div class="stack">
      <p>
        <Chip tone={failed ? 'bad' : 'info'}>{stateLabel(status.state)}</Chip> {stateText(status.state)}
      </p>
      {failed && (
        <Notice tone="bad" title="The switch failed">
          {status.error || 'The server reported a failure.'} The source stays fenced. Roll back to resume it.
        </Notice>
      )}
      {!failed && (
        <div>
          <label for="switch-progress">
            Progress: {p?.phase ?? status.state}
            {p ? ` (${Math.round(p.percent)}%)` : ''}
          </label>
          <progress id="switch-progress" max={100} value={p ? p.percent : undefined}>
            {p ? `${Math.round(p.percent)}%` : ''}
          </progress>
          {p?.rowsDone !== undefined && p.rowsTotal !== undefined && (
            <p class="muted small">
              {formatNumber(p.rowsDone)} of {formatNumber(p.rowsTotal)} rows
            </p>
          )}
        </div>
      )}
      {status.state === 'fenced' && (
        <Notice tone="info">
          The source is fenced. At most one side may ever dispatch mail, so the source will not accept or send until you roll back, even after a restart. This page keeps updating on its own; you do not need to stay.
        </Notice>
      )}
      {error !== undefined && error !== null && <ErrorNotice error={error} />}
      {canRollback && (
        <div class="row">
          <RollbackControl onRollback={onRollback} busy={busy} error={error} />
          <span class="muted small">Rollback is available until you activate.</span>
        </div>
      )}
    </div>
  );
}

/** Step 5: verification report, explicit Confirm. A failed report offers only rollback. */
export function VerifyStep({
  status,
  canConfirm,
  onConfirm,
  onRollback,
  busy,
  error,
}: {
  status: SwitchStatus;
  canConfirm: boolean;
  onConfirm: () => void;
  onRollback: () => Promise<unknown>;
  busy: boolean;
  error: unknown;
}) {
  const report = status.verifyReport;
  const ok = report?.ok === true;
  return (
    <div class="stack">
      {report ? (
        <>
          <p>
            <Chip tone={ok ? 'ok' : 'bad'}>{ok ? 'verification passed' : 'verification failed'}</Chip> <Chip tone={report.checksumsOk ? 'ok' : 'bad'}>{report.checksumsOk ? 'checksums match' : 'checksum mismatch'}</Chip>
          </p>
          <div class="table-wrap">
            <table>
              <caption class="sr-only">Row counts per table, expected from the manifest and actual in the target</caption>
              <thead>
                <tr>
                  <th scope="col">Table</th>
                  <th scope="col" class="num">
                    Expected
                  </th>
                  <th scope="col" class="num">
                    Actual
                  </th>
                  <th scope="col">Result</th>
                </tr>
              </thead>
              <tbody>
                {report.tables.map((t) => (
                  <tr key={t.table}>
                    <th scope="row">
                      <code>{t.table}</code>
                    </th>
                    <td class="num">{formatNumber(t.expected)}</td>
                    <td class="num">{formatNumber(t.actual)}</td>
                    <td>{t.expected === t.actual ? <Chip tone="ok">match</Chip> : <Chip tone="bad">differs</Chip>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <Notice tone="warn">The server did not return a verification report. Do not confirm; roll back or reload.</Notice>
      )}
      {ok ? (
        <Notice tone="info" title="Nothing is live yet">
          Confirming records your approval. The target still does not send mail until you activate it in the next step.
        </Notice>
      ) : (
        <Notice tone="bad" title="Do not continue">
          The target does not match the source. Only rollback is offered; the source resumes unchanged.
        </Notice>
      )}
      {error !== undefined && error !== null && <ErrorNotice error={error} />}
      <div class="row">
        {canConfirm && (
          <Button variant="primary" onClick={onConfirm} busy={busy}>
            Confirm the verified target
          </Button>
        )}
        <RollbackControl onRollback={onRollback} busy={busy} error={error} />
      </div>
    </div>
  );
}
