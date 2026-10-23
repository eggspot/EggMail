import { useReducer, useState } from 'preact/hooks';
import { api } from '../../api/endpoints';
import type { PreflightReport, SwitchState, SwitchStatus } from '../../api/types';
import { ActivateStep, DoneStep, FinalizeStep } from '../../components/switch/FinishSteps';
import { ChooseStep } from '../../components/switch/ChooseStep';
import type { Secrets } from '../../components/switch/ChooseStep';
import { PreflightStep } from '../../components/switch/PreflightStep';
import { ProgressStep, VerifyStep } from '../../components/switch/RunningSteps';
import { StartStep } from '../../components/switch/StartStep';
import { Stepper } from '../../components/switch/Stepper';
import { isPoolPressure, PressureIndicators } from '../../components/PressureIndicators';
import { Card, Chip, ErrorNotice, Loading, Notice, PageHeader } from '../../components/ui';
import { useAction, useApi, useDocumentTitle, usePolling } from '../../lib/hooks';
import { allowedActions, buildRequest, flowReducer, initialForm, initialLocal, isRunning, stateLabel, stateText, stepFor } from '../../lib/switchFlow';
import type { SwitchForm } from '../../lib/switchFlow';
import { useApp } from '../../state/app';

const POLL_MS = 2000;

/**
 * Guided storage switch. Every state change is the result of an explicit click in this page: nothing is
 * started, confirmed, activated, rolled back or finalized automatically, and the advisory pressure
 * indicators only inform. The server state is authoritative, so reloading resumes at the right step.
 */
export default function StorageSwitch(_props: Record<string, unknown>) {
  useDocumentTitle('Storage switch');
  const { capabilities, refreshCapabilities } = useApp();
  const currentBackend = capabilities?.backend ?? 'sqlite';

  const status = useApi(() => api.switchStatus(), []);
  const admin = useApi(() => api.adminStatus(), []);
  const [local, dispatch] = useReducer(flowReducer, initialLocal);
  const [form, setForm] = useState<SwitchForm>(() => initialForm(currentBackend));
  const [secrets, setSecrets] = useState<Secrets>({ passphrase: '', repeat: '' });
  const [report, setReport] = useState<PreflightReport | undefined>();
  const [dismissedDone, setDismissedDone] = useState(false);

  const state: SwitchState = status.data?.state ?? 'none';
  const current: SwitchStatus = status.data ?? { state: 'none' };

  // Poll only while the server is doing long-running work; stops on its own at the next stable state.
  usePolling(
    async () => {
      try {
        const next = await api.switchStatus();
        status.setData(next);
        return isRunning(next.state);
      } catch {
        return true; // keep trying; the error surfaces on the next explicit action or reload
      }
    },
    POLL_MS,
    isRunning(state),
  );

  const apply = (next: SwitchStatus | undefined) => {
    if (next) status.setData(next);
    admin.reload();
    void refreshCapabilities();
  };

  const preflight = useAction(async () => {
    const r = await api.switchPreflight(buildRequest(form));
    setReport(r);
    dispatch({ type: 'preflight-done', ok: r.ok });
  });
  const start = useAction(async (confirmation: string) => {
    setDismissedDone(false);
    const next = await api.switchStart({ ...buildRequest(form), exportPassphrase: secrets.passphrase, confirmation });
    setSecrets({ passphrase: '', repeat: '' }); // the passphrase is held in memory only until the switch starts
    dispatch({ type: 'reset' });
    apply(next);
  });
  const confirm = useAction(async () => apply(await api.switchConfirm()));
  const activate = useAction(async () => apply(await api.switchActivate()));
  const finalize = useAction(async () => apply(await api.switchFinalize()));
  const rollback = useAction(async () => {
    const next = await api.switchRollback();
    dispatch({ type: 'reset' });
    apply(next);
  });

  if (status.loading && !status.data) {
    return (
      <>
        <PageHeader title="Storage switch" />
        <Loading />
      </>
    );
  }
  if (status.error && !status.data) {
    return (
      <>
        <PageHeader title="Storage switch" />
        <ErrorNotice error={status.error} onRetry={status.reload} />
      </>
    );
  }

  // After a finalized switch the user may plan another one; the server state stays 'finalized' until then.
  const effective: SwitchState = state === 'finalized' && dismissedDone ? 'none' : state;
  const step = stepFor(effective, local);
  const actions = allowedActions(state, current.verifyReport?.ok);
  const rollbackAction = async () => {
    await rollback.run();
  };

  return (
    <>
      <PageHeader
        title="Storage switch"
        subtitle="Move between SQLite and PostgreSQL. Manual, guided and reversible until you activate. EggMail never switches by itself."
        actions={
          <Chip tone={state === 'failed' ? 'bad' : state === 'none' ? 'neutral' : 'info'} title={stateText(state)}>
            {stateLabel(state)}
          </Chip>
        }
      />

      {/* The pool card of PostgreSQL (decision 109) is left out here: a busy pool is never a reason to switch. */}
      {admin.data?.pressure && !isPoolPressure(admin.data.pressure) && <PressureIndicators pressure={admin.data.pressure} showLink={false} />}

      {state === 'rolled_back' && step === 'choose' && (
        <Notice tone="info" title="The last switch was rolled back">
          The source is active again and nothing from the target was used. You can plan a new switch below.
        </Notice>
      )}

      <Stepper step={step} />

      <Card title={heading(step)}>
        <div aria-live="polite">
          {step === 'choose' && (
            <ChooseStep
              currentBackend={currentBackend}
              form={form}
              onForm={setForm}
              secrets={secrets}
              onSecrets={setSecrets}
              busy={preflight.busy}
              error={preflight.error}
              onPreflight={() => void preflight.run()}
            />
          )}
          {step === 'preflight' && report && (
            <PreflightStep report={report} form={form} onBack={() => dispatch({ type: 'back' })} onContinue={() => dispatch({ type: 'proceed' })} />
          )}
          {step === 'start' && (
            <StartStep currentBackend={currentBackend} form={form} busy={start.busy} error={start.error} onBack={() => dispatch({ type: 'back' })} onStart={(c) => void start.run(c)} />
          )}
          {step === 'progress' && <ProgressStep status={current} canRollback={actions.rollback} onRollback={rollbackAction} busy={rollback.busy} error={rollback.error} />}
          {step === 'verify' && (
            <VerifyStep
              status={current}
              canConfirm={actions.confirm}
              onConfirm={() => void confirm.run()}
              onRollback={rollbackAction}
              busy={confirm.busy || rollback.busy}
              error={confirm.error ?? rollback.error}
            />
          )}
          {step === 'activate' && (
            <ActivateStep status={current} onActivate={() => void activate.run()} onRollback={rollbackAction} busy={activate.busy || rollback.busy} error={activate.error ?? rollback.error} />
          )}
          {step === 'finalize' && <FinalizeStep status={current} onFinalize={() => void finalize.run()} busy={finalize.busy} error={finalize.error} />}
          {step === 'done' && <DoneStep status={current} onAgain={() => {
                dispatch({ type: 'reset' });
                setForm(initialForm(currentBackend));
                setDismissedDone(true);
              }} />}
        </div>
      </Card>
    </>
  );
}

function heading(step: string): string {
  switch (step) {
    case 'choose':
      return '1. Choose the switch';
    case 'preflight':
      return '2. Preflight report';
    case 'start':
      return '3. Start the switch';
    case 'progress':
      return '4. Progress';
    case 'verify':
      return '5. Verify and confirm';
    case 'activate':
      return '6. Activate the target';
    case 'finalize':
      return '7. Finalize';
    default:
      return 'Done';
  }
}
