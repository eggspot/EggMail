// Pure logic of the storage switch wizard (design 4.6): which step the server state maps to, which actions
// are allowed, the local (pre-start) step machine, and form helpers. No I/O and no UI here, so it is easy
// to test exhaustively. Rule that this module encodes: every action that changes anything is an explicit,
// user-triggered step; nothing is ever inferred from advisory indicators.
import type { SwitchInclude, SwitchMode, SwitchRequest, SwitchState, SwitchTarget, SwitchTargetConfig } from '../api/types';

export const PASSPHRASE_MIN_LENGTH = 12;
export const QUIESCE_TIMEOUT_SECONDS = 30;

/** States in which the server is working and the page should poll. */
export const RUNNING_STATES: readonly SwitchState[] = ['draining', 'quiescing', 'fenced', 'exporting', 'importing', 'verifying'];
/** States before activation in which rollback is allowed (the old store is still the source of truth). */
export const ROLLBACK_STATES: readonly SwitchState[] = ['draining', 'quiescing', 'fenced', 'exporting', 'importing', 'verifying', 'verified', 'confirmed', 'failed'];
/** States in which no switch is in flight and a new one may be started. */
export const IDLE_STATES: readonly SwitchState[] = ['none', 'rolled_back', 'finalized'];

export type WizardStep = 'choose' | 'preflight' | 'start' | 'progress' | 'verify' | 'activate' | 'finalize' | 'done';

export const STEP_ORDER: { id: Exclude<WizardStep, 'done'>; label: string }[] = [
  { id: 'choose', label: 'Choose' },
  { id: 'preflight', label: 'Preflight' },
  { id: 'start', label: 'Start' },
  { id: 'progress', label: 'Progress' },
  { id: 'verify', label: 'Verify and confirm' },
  { id: 'activate', label: 'Activate' },
  { id: 'finalize', label: 'Finalize' },
];

export function isRunning(state: SwitchState): boolean {
  return RUNNING_STATES.includes(state);
}
export function isIdle(state: SwitchState): boolean {
  return IDLE_STATES.includes(state);
}

// ---------- local (pre-start) step machine ----------

export type LocalStep = 'choose' | 'preflight' | 'start';
export interface FlowLocal {
  step: LocalStep;
  preflightOk: boolean;
}
export type FlowAction = { type: 'preflight-done'; ok: boolean } | { type: 'back' } | { type: 'proceed' } | { type: 'reset' };

export const initialLocal: FlowLocal = { step: 'choose', preflightOk: false };

/** Illegal transitions return the same state object. */
export function flowReducer(s: FlowLocal, a: FlowAction): FlowLocal {
  switch (a.type) {
    case 'preflight-done':
      return s.step === 'choose' ? { step: 'preflight', preflightOk: a.ok } : s;
    case 'back':
      if (s.step === 'preflight') return { step: 'choose', preflightOk: false };
      if (s.step === 'start') return { step: 'preflight', preflightOk: s.preflightOk };
      return s;
    case 'proceed':
      return s.step === 'preflight' && s.preflightOk ? { step: 'start', preflightOk: true } : s;
    case 'reset':
      return initialLocal;
  }
}

/** The step to show, from the server state (authoritative once a switch exists) and the local step. */
export function stepFor(state: SwitchState, local: FlowLocal): WizardStep {
  switch (state) {
    case 'none':
    case 'rolled_back':
      return local.step;
    case 'finalized':
      return local.step === 'choose' ? 'done' : local.step;
    case 'draining':
    case 'quiescing':
    case 'fenced':
    case 'exporting':
    case 'importing':
    case 'verifying':
    case 'failed':
      return 'progress';
    case 'verified':
      return 'verify';
    case 'confirmed':
      return 'activate';
    case 'active':
      return 'finalize';
    default:
      // A state this dashboard does not know (a newer server) is treated as work in progress, never as a blank page.
      return 'progress';
  }
}

/** The label of a state; an unknown one (a newer server) is shown as it is. */
export function stateLabel(state: string): string {
  return (STATE_LABEL as Record<string, string | undefined>)[state] ?? state;
}

export function stepIndex(step: WizardStep): number {
  if (step === 'done') return STEP_ORDER.length;
  return STEP_ORDER.findIndex((s) => s.id === step);
}

// ---------- allowed actions ----------

export interface AllowedActions {
  start: boolean;
  confirm: boolean;
  activate: boolean;
  rollback: boolean;
  finalize: boolean;
  /** After activation going back means running the same flow in reverse (never a rollback). */
  reverseSwitchOnly: boolean;
}

export function allowedActions(state: SwitchState, verifyOk: boolean | undefined): AllowedActions {
  return {
    start: isIdle(state),
    confirm: state === 'verified' && verifyOk === true,
    activate: state === 'confirmed',
    rollback: ROLLBACK_STATES.includes(state),
    finalize: state === 'active',
    reverseSwitchOnly: state === 'active',
  };
}

const STATE_TEXT: Record<SwitchState, string> = {
  none: 'No switch is in progress. Choose a target and run the preflight checks.',
  draining: 'Draining: the server has stopped accepting mail and is waiting for the queue to empty. Nothing is moved while it drains.',
  quiescing: 'Quiescing: the server has stopped accepting mail and is letting in-flight deliveries finish.',
  fenced: 'The source is fenced: it no longer accepts or sends mail. It stays read-only until you finalize.',
  exporting: 'Exporting the bundle from the source.',
  importing: 'Importing the bundle into the target. The target does not send mail until it is activated.',
  verifying: 'Verifying the target: comparing row counts and checksums with the bundle. The report appears when it is done.',
  verified: 'The target has been verified. Review the report, then confirm. Nothing has gone live yet.',
  confirmed: 'Confirmed. Activate to make the target the live store.',
  active: 'The target is live. Finalize when you are satisfied; the old data is never deleted by EggMail.',
  finalized: 'The switch is finalized. The old store is untouched and can be removed by you.',
  rolled_back: 'The switch was rolled back. The source is active again and the imported data was discarded.',
  failed: 'The switch failed. The source stays fenced until you roll back.',
};

export function stateText(state: SwitchState): string {
  return STATE_TEXT[state] ?? `The server reports the state "${state}".`;
}

export const STATE_LABEL: Record<SwitchState, string> = {
  none: 'no switch',
  draining: 'draining',
  quiescing: 'quiescing',
  fenced: 'source fenced',
  exporting: 'exporting',
  importing: 'importing',
  verifying: 'verifying',
  verified: 'verified',
  confirmed: 'confirmed',
  active: 'active (target live)',
  finalized: 'finalized',
  rolled_back: 'rolled back',
  failed: 'failed',
};

// ---------- form helpers ----------

export interface SwitchForm {
  to: SwitchTarget;
  mode: SwitchMode;
  includeQueue: boolean;
  includeHistory: boolean;
  connectionName: string;
  host: string;
  port: string;
  database: string;
  path: string;
}

/** Switching is symmetric: the default direction is always the other backend. */
export function defaultTarget(currentBackend: string | undefined): SwitchTarget {
  return currentBackend === 'postgres' ? 'sqlite' : 'postgres';
}

export function initialForm(currentBackend: string | undefined): SwitchForm {
  return {
    to: defaultTarget(currentBackend),
    mode: 'drain',
    includeQueue: false,
    includeHistory: true,
    connectionName: '',
    host: '',
    port: '5432',
    database: '',
    path: '/data',
  };
}

/** Queued mail only moves with quiesce; a drain empties the queue first. */
export function normalizeForm(f: SwitchForm): SwitchForm {
  return f.mode === 'drain' && f.includeQueue ? { ...f, includeQueue: false } : f;
}

export function includeList(f: SwitchForm): SwitchInclude[] {
  const n = normalizeForm(f);
  const out: SwitchInclude[] = [];
  if (n.includeQueue) out.push('queue');
  if (n.includeHistory) out.push('history');
  return out;
}

export function targetConfig(f: SwitchForm): SwitchTargetConfig {
  if (f.to === 'sqlite') return { path: f.path.trim() };
  const t: SwitchTargetConfig = {};
  if (f.connectionName.trim()) t.connectionName = f.connectionName.trim();
  else {
    t.host = f.host.trim();
    const port = Number(f.port);
    if (Number.isInteger(port) && port > 0) t.port = port;
    t.database = f.database.trim();
  }
  return t;
}

export function buildRequest(f: SwitchForm): SwitchRequest {
  const n = normalizeForm(f);
  return { to: n.to, target: targetConfig(n), include: includeList(n), mode: n.mode };
}

export function validateForm(f: SwitchForm): Record<string, string> {
  const errors: Record<string, string> = {};
  if (f.to === 'sqlite') {
    if (!f.path.trim()) errors.path = 'Enter the data directory for the SQLite files.';
  } else if (!f.connectionName.trim()) {
    if (!f.host.trim()) errors.host = 'Enter a host, or a connection name instead.';
    if (!f.database.trim()) errors.database = 'Enter the database name.';
    const port = Number(f.port);
    if (f.port.trim() && !(Number.isInteger(port) && port > 0 && port < 65536)) errors.port = 'Enter a port between 1 and 65535.';
  }
  return errors;
}

export function validatePassphrase(passphrase: string, repeat: string): { passphrase?: string; repeat?: string } {
  const errors: { passphrase?: string; repeat?: string } = {};
  if (passphrase.length < PASSPHRASE_MIN_LENGTH) errors.passphrase = `Use at least ${PASSPHRASE_MIN_LENGTH} characters.`;
  if (repeat !== passphrase) errors.repeat = 'The two passphrases do not match.';
  return errors;
}

export function confirmationPhrase(to: SwitchTarget): string {
  return `switch to ${to}`;
}

export function confirmationMatches(to: SwitchTarget, typed: string): boolean {
  return typed.trim() === confirmationPhrase(to);
}

export function backendLabel(b: string): string {
  return b === 'postgres' ? 'PostgreSQL' : b === 'sqlite' ? 'SQLite' : b;
}
