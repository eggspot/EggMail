import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/preact';
import StorageSwitch from '../src/pages/admin/StorageSwitch';
import type { AdminStatus, PreflightReport, SwitchState, SwitchStatus } from '../src/api/types';
import { mockFetch, renderWithApp, problem } from './helpers';

const SW = '/api/v1/admin/storage/switch';
const MUTATING = ['preflight', 'start', 'confirm', 'activate', 'rollback', 'finalize'].map((a) => `${SW}/${a}`);

const okReport = { ok: true, tables: [{ table: 'config.tenants', expected: 3, actual: 3 }], checksumsOk: true };
const badReport = { ok: false, tables: [{ table: 'history.events', expected: 100, actual: 90 }], checksumsOk: false };

function status(state: SwitchState, over: Partial<SwitchStatus> = {}): SwitchStatus {
  return { switchId: 'sw1', state, direction: { from: 'sqlite', to: 'postgres' }, mode: 'drain', include: ['history'], orchestratorManaged: false, ...over };
}

function adminStatus(advisory = false): AdminStatus {
  return {
    version: '0.1.0',
    backend: 'sqlite',
    historyMode: 'full',
    queue: { depth: 3, deferred: 0 },
    storage: { healthy: true, warnings: [] },
    certificates: [],
    pressure: { writerQueueDepth: advisory ? 1500 : 10, writerQueueOverThresholdSeconds: advisory ? 400 : 0, commitP99Ms: advisory ? 130 : 5, advisory },
    switch: { state: 'none' },
  };
}

const report = (over: Partial<PreflightReport> = {}): PreflightReport => ({
  ok: true,
  checks: [
    { name: 'Target reachable', ok: true, severity: 'info', message: 'Connected.' },
    { name: 'SQLite sync mode', ok: true, severity: 'warning', message: 'synchronous=OFF on the target.' },
  ],
  counts: { queuedMessages: 4, historyRows: 1000, historyBytes: 5_000_000, statsRows: 200 },
  estimate: { seconds: 90, bytes: 6_000_000, unverified: true },
  notCarried: ['Deployment configuration stays with your deployment.'],
  orchestratorManaged: false,
  ...over,
});

function setup(initial: SwitchStatus, extra: Record<string, unknown> = {}, advisory = false) {
  let current = initial;
  const m = mockFetch({
    [`GET ${SW}`]: () => current,
    'GET /api/v1/admin/status': () => adminStatus(advisory),
    'GET /api/v1/capabilities': () => ({ version: '0.1.0', backend: 'sqlite', history: { mode: 'full' }, content: {}, limits: {}, inbound: { enabled: false }, warnings: [] }),
    ...extra,
  });
  return { m, set: (s: SwitchStatus) => (current = s) };
}

const currentStep = (c: Element) => c.querySelector('.steps [aria-current="step"]')?.textContent ?? '';
const mutatingCalls = (m: ReturnType<typeof mockFetch>) => m.calls.filter((c) => c.method === 'POST' && MUTATING.includes(c.path));

async function render() {
  const r = renderWithApp(<StorageSwitch />, { role: 'admin' });
  await screen.findByRole('list', { name: 'Storage switch steps' });
  return r;
}

afterEach(() => {
  vi.useRealTimers();
  cleanup();
});

describe('StorageSwitch resumes from the server state', () => {
  const cases: [SwitchState, string, RegExp][] = [
    ['none', 'Choose', /run preflight checks/i],
    ['draining', 'Progress', /draining/i],
    ['quiescing', 'Progress', /quiescing/i],
    ['fenced', 'Progress', /source is fenced/i],
    ['exporting', 'Progress', /exporting/i],
    ['importing', 'Progress', /importing/i],
    ['verifying', 'Progress', /verifying/i],
    ['failed', 'Progress', /the switch failed/i],
    ['verified', 'Verify and confirm', /confirm the verified target/i],
    ['confirmed', 'Activate', /activate the target/i],
    ['active', 'Finalize', /finalize the switch/i],
    ['finalized', 'Finalize', /switch finalized/i],
  ];
  for (const [state, step, text] of cases) {
    it(`state ${state} -> ${step}`, async () => {
      const extra = state === 'verified' ? { verifyReport: okReport } : {};
      setup(status(state, { progress: { phase: state, percent: 40, rowsDone: 10, rowsTotal: 25 }, error: 'boom', ...extra }));
      const { container } = await render();
      await screen.findAllByText(text);
      if (state !== 'finalized') expect(currentStep(container)).toBe(step);
    });
  }

  it('does not poll or mutate when idle or waiting for a decision', async () => {
    const { m } = setup(status('verified', { verifyReport: okReport }));
    await render();
    await screen.findByRole('button', { name: /confirm the verified target/i });
    expect(mutatingCalls(m)).toHaveLength(0);
  });
});

describe('guided flow from the start', () => {
  const preflightRoute = { [`POST ${SW}/preflight`]: () => report() };

  async function fillChoose() {
    fireEvent.input(await screen.findByLabelText('Host'), { target: { value: 'db.internal' } });
    fireEvent.input(screen.getByLabelText('Database'), { target: { value: 'eggmail' } });
    fireEvent.input(screen.getByLabelText('Passphrase'), { target: { value: 'a-long-enough-pass' } });
    fireEvent.input(screen.getByLabelText('Repeat passphrase'), { target: { value: 'a-long-enough-pass' } });
  }

  it('defaults to the opposite backend, drain, and explains both modes', async () => {
    setup(status('none'));
    await render();
    expect(screen.getByTestId('direction').textContent).toMatch(/SQLite to PostgreSQL/);
    expect((screen.getByLabelText(/Drain \(safe default\)/) as HTMLInputElement).checked).toBe(true);
    expect(screen.getByText(/Switch:QuiesceTimeoutSeconds/)).toBeTruthy();
    expect((screen.getByLabelText(/Queued mail/) as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/Quiesce\./));
    expect((screen.getByLabelText(/Queued mail/) as HTMLInputElement).disabled).toBe(false);
    expect(screen.getByText(/History can be large/)).toBeTruthy();
    expect(screen.getByText(/unverified/)).toBeTruthy();
  });

  it('blocks preflight for a short or mismatched passphrase and shows the errors', async () => {
    const { m } = setup(status('none'), preflightRoute);
    await render();
    fireEvent.input(await screen.findByLabelText('Host'), { target: { value: 'h' } });
    fireEvent.input(screen.getByLabelText('Database'), { target: { value: 'd' } });
    fireEvent.input(screen.getByLabelText('Passphrase'), { target: { value: 'short' } });
    fireEvent.input(screen.getByLabelText('Repeat passphrase'), { target: { value: 'other' } });
    fireEvent.click(screen.getByRole('button', { name: /run preflight checks/i }));
    expect(await screen.findByText(/Use at least 12 characters/)).toBeTruthy();
    expect(screen.getByText(/do not match/)).toBeTruthy();
    expect(m.callsTo('POST', `${SW}/preflight`)).toHaveLength(0);
  });

  it('requires a target, then preflight, then the typed phrase before Start; Start sends the passphrase and confirmation', async () => {
    const { m, set } = setup(status('none'), {
      ...preflightRoute,
      [`POST ${SW}/start`]: () => {
        const s = status('draining', { progress: { phase: 'draining', percent: 5 } });
        set(s);
        return s;
      },
    });
    const { container } = await render();

    fireEvent.click(screen.getByRole('button', { name: /run preflight checks/i }));
    expect(await screen.findByText(/Enter a host/)).toBeTruthy();
    expect(m.callsTo('POST', `${SW}/preflight`)).toHaveLength(0);

    await fillChoose();
    fireEvent.click(screen.getByRole('button', { name: /run preflight checks/i }));
    await screen.findByText(/Preflight passed/);
    expect(currentStep(container)).toBe('Preflight');
    expect(m.callsTo('POST', `${SW}/preflight`)[0].body).toEqual({ to: 'postgres', mode: 'drain', include: ['history'], target: { host: 'db.internal', port: 5432, database: 'eggmail' } });
    expect(screen.getByText(/What will not carry over/)).toBeTruthy();
    expect(screen.getByText('unverified, not measured')).toBeTruthy();
    expect(screen.getByText('Warning')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(currentStep(container)).toBe('Start');
    const startBtn = screen.getByRole('button', { name: 'Start switch' }) as HTMLButtonElement;
    expect(startBtn.disabled).toBe(true);
    expect(m.callsTo('POST', `${SW}/start`)).toHaveLength(0);

    const phrase = screen.getByLabelText(/Type "switch to postgres" to confirm/);
    fireEvent.input(phrase, { target: { value: 'switch to sqlite' } });
    expect(startBtn.disabled).toBe(true);
    fireEvent.input(phrase, { target: { value: 'switch to postgres' } });
    expect(startBtn.disabled).toBe(false);
    expect(screen.getByText(/Nothing is deleted/)).toBeTruthy();

    fireEvent.click(startBtn);
    await waitFor(() => expect(m.callsTo('POST', `${SW}/start`)).toHaveLength(1));
    expect(m.callsTo('POST', `${SW}/start`)[0].body).toMatchObject({ to: 'postgres', exportPassphrase: 'a-long-enough-pass', confirmation: 'switch to postgres' });
    await screen.findByRole('progressbar', { hidden: true }).catch(() => undefined);
    await waitFor(() => expect(currentStep(container)).toBe('Progress'));
  });

  it('keeps Continue disabled when preflight reports problems', async () => {
    setup(status('none'), { [`POST ${SW}/preflight`]: () => report({ ok: false, checks: [{ name: 'Target reachable', ok: false, severity: 'error', message: 'timeout' }] }) });
    await render();
    await fillChoose();
    fireEvent.click(screen.getByRole('button', { name: /run preflight checks/i }));
    await screen.findByText(/Preflight found problems/);
    expect((screen.getByRole('button', { name: 'Continue' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('Problem')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(screen.getByRole('button', { name: /run preflight checks/i })).toBeTruthy();
  });

  it('shows server-side preflight errors', async () => {
    setup(status('none'), { [`POST ${SW}/preflight`]: () => problem(400, 'validation_failed', { errors: [{ field: 'to', message: 'the server already uses postgres' }] }) });
    await render();
    await fillChoose();
    fireEvent.click(screen.getByRole('button', { name: /run preflight checks/i }));
    expect(await screen.findByText(/Preflight could not run/)).toBeTruthy();
    expect(screen.getByText(/already uses postgres/)).toBeTruthy();
  });

  it('notes the orchestrator-managed configuration in the preflight report', async () => {
    setup(status('none'), { [`POST ${SW}/preflight`]: () => report({ orchestratorManaged: true }) });
    await render();
    await fillChoose();
    fireEvent.click(screen.getByRole('button', { name: /run preflight checks/i }));
    expect(await screen.findByText(/never rewrites those/)).toBeTruthy();
  });
});

describe('explicit actions only', () => {
  it('never mutates on load, even when the advisory thresholds are exceeded', async () => {
    const { m } = setup(status('none'), {}, true);
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await render();
    await screen.findByText(/advisory indicators only/i);
    expect(screen.getByText(/you can start a switch yourself/i)).toBeTruthy();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(mutatingCalls(m)).toHaveLength(0);
    expect(screen.getByText(/never switches storage by itself/i)).toBeTruthy();
  });

  it('confirm, activate and finalize each need their own click', async () => {
    const { m, set } = setup(status('verified', { verifyReport: okReport }), {
      [`POST ${SW}/confirm`]: () => {
        const s = status('confirmed');
        set(s);
        return s;
      },
      [`POST ${SW}/activate`]: () => {
        const s = status('active');
        set(s);
        return s;
      },
      [`POST ${SW}/finalize`]: () => {
        const s = status('finalized');
        set(s);
        return s;
      },
    });
    const { container } = await render();
    expect(mutatingCalls(m)).toHaveLength(0);
    fireEvent.click(await screen.findByRole('button', { name: /confirm the verified target/i }));
    await screen.findByRole('button', { name: /activate the target/i });
    expect(currentStep(container)).toBe('Activate');
    expect(m.callsTo('POST', `${SW}/activate`)).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: /activate the target/i }));
    await screen.findByRole('button', { name: /finalize the switch/i });
    expect(m.callsTo('POST', `${SW}/finalize`)).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: /finalize the switch/i }));
    await screen.findByText(/Switch finalized/);
    expect(mutatingCalls(m).map((c) => c.path.split('/').pop())).toEqual(['confirm', 'activate', 'finalize']);
  });

  it('offers only rollback when verification failed', async () => {
    setup(status('verified', { verifyReport: badReport }));
    await render();
    await screen.findByText(/verification failed/i);
    expect(screen.queryByRole('button', { name: /confirm the verified target/i })).toBeNull();
    expect(screen.getByRole('button', { name: 'Roll back' })).toBeTruthy();
    expect(screen.getByText('differs')).toBeTruthy();
  });

  it('rolls back through a confirmation dialog and returns to the first step', async () => {
    const { m, set } = setup(status('fenced'), {
      [`POST ${SW}/rollback`]: () => {
        const s = status('rolled_back');
        set(s);
        return s;
      },
    });
    const { container } = await render();
    fireEvent.click(await screen.findByRole('button', { name: 'Roll back' }));
    const dialog = await screen.findByRole('dialog');
    expect(m.callsTo('POST', `${SW}/rollback`)).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Roll back' }));
    await waitFor(() => expect(m.callsTo('POST', `${SW}/rollback`)).toHaveLength(1));
    await screen.findByText(/last switch was rolled back/i);
    expect(currentStep(container)).toBe('Choose');
  });

  it('cancelling the rollback dialog changes nothing', async () => {
    const { m } = setup(status('importing', { progress: { phase: 'importing', percent: 70 } }));
    await render();
    fireEvent.click(await screen.findByRole('button', { name: 'Roll back' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(mutatingCalls(m)).toHaveLength(0);
  });

  it('hides rollback after activation and explains the reverse flow', async () => {
    setup(status('active'));
    await render();
    await screen.findByText(/Rollback is no longer available/);
    expect(screen.queryByRole('button', { name: /roll back/i })).toBeNull();
    expect(screen.getByText(/run this same flow in reverse/)).toBeTruthy();
    expect(screen.getByText(/never deletes the source/)).toBeTruthy();
  });

  it('shows rollback for the failed state with the error', async () => {
    setup(status('failed', { error: 'target disk full' }));
    await render();
    expect(await screen.findByText(/target disk full/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Roll back' })).toBeTruthy();
  });

  it('shows a server error from a refused action', async () => {
    setup(status('verified', { verifyReport: okReport }), { [`POST ${SW}/confirm`]: () => problem(409, 'validation_failed', { detail: 'switch is not in state verified' }) });
    await render();
    fireEvent.click(await screen.findByRole('button', { name: /confirm the verified target/i }));
    expect(await screen.findByText(/not valid|switch is not in state/i)).toBeTruthy();
  });
});

describe('what activation produced', () => {
  it('shows the cutover patch of an orchestrator-managed deployment on the finalize step, because the server creates it on activation', async () => {
    setup(status('active', { orchestratorManaged: true, cutoverPatch: { kind: 'patch', text: 'Storage__Backend=Postgres\n' } }));
    await render();
    expect(await screen.findByRole('heading', { name: '7. Finalize' })).toBeTruthy();
    expect((await screen.findByTestId('cutover-patch')).textContent).toContain('Storage__Backend=Postgres');
    expect(screen.getByRole('button', { name: /copy cutover patch/i })).toBeTruthy();
  });

  it('shows the note about the rewritten bootstrap file otherwise', async () => {
    setup(status('active', { cutoverPatch: { kind: 'bootstrap', text: 'The bootstrap file /data/bootstrap.json now points at the postgres target.' } }));
    await render();
    expect((await screen.findByTestId('activation-note')).textContent).toContain('bootstrap file /data/bootstrap.json');
    expect(screen.queryByTestId('cutover-patch')).toBeNull();
  });

  it('shows nothing extra when the server (after a restart) has no activation result', async () => {
    setup(status('active', { cutoverPatch: null }));
    await render();
    await screen.findByRole('heading', { name: '7. Finalize' });
    expect(screen.queryByTestId('cutover-patch')).toBeNull();
    expect(screen.queryByTestId('activation-note')).toBeNull();
  });

  it('explains a refused finalize with the reason the server gives (not_ready is not always an outage)', async () => {
    setup(status('active'), {
      [`POST ${SW}/finalize`]: () => problem(503, 'not_ready', { detail: "The former source is not described (SwitchSource:*). Finalize with 'mta migrate-storage finalize' instead." }),
    });
    await render();
    fireEvent.click(await screen.findByRole('button', { name: 'Finalize the switch' }));
    expect(await screen.findByText(/mta migrate-storage finalize/)).toBeTruthy();
  });
});

describe('cutover patch', () => {
  it('is shown, with a copy button, only for orchestrator-managed deployments', async () => {
    setup(status('confirmed', { orchestratorManaged: true, cutoverPatch: { kind: 'environment', text: 'Storage__Backend=Postgres\n' } }));
    await render();
    const patch = await screen.findByTestId('cutover-patch');
    expect(patch.textContent).toContain('Storage__Backend=Postgres');
    expect(patch.className).toContain('patch');
    expect(screen.getByRole('button', { name: /copy cutover patch/i })).toBeTruthy();
    expect(screen.getByText(/never rewrites environment variables/)).toBeTruthy();
  });

  it('is absent for bootstrap-file deployments, which restart automatically', async () => {
    setup(status('confirmed', { orchestratorManaged: false, cutoverPatch: null }));
    await render();
    await screen.findByText(/Bootstrap-file deployment/);
    expect(screen.queryByTestId('cutover-patch')).toBeNull();
  });
});

describe('polling', () => {
  it('polls only while the server is working and stops at a stable state', async () => {
    let n = 0;
    const states: SwitchStatus[] = [
      status('exporting', { progress: { phase: 'exporting', percent: 30 } }),
      status('exporting', { progress: { phase: 'exporting', percent: 60 } }),
      status('verified', { verifyReport: okReport }),
    ];
    const { m } = setup(status('exporting'), { [`GET ${SW}`]: () => states[Math.min(n++, states.length - 1)] });
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { container } = await render();
    expect(currentStep(container)).toBe('Progress');
    const polls = () => m.callsTo('GET', SW).length;
    const afterLoad = polls();
    await vi.advanceTimersByTimeAsync(2100);
    expect(polls()).toBeGreaterThan(afterLoad);
    await vi.advanceTimersByTimeAsync(2100);
    await waitFor(() => expect(currentStep(container)).toBe('Verify and confirm'));
    const settled = polls();
    await vi.advanceTimersByTimeAsync(20_000);
    expect(polls()).toBe(settled);
    expect(mutatingCalls(m)).toHaveLength(0);
  });

  it('does not poll at all while idle', async () => {
    const { m } = setup(status('none'));
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await render();
    const before = m.callsTo('GET', SW).length;
    await vi.advanceTimersByTimeAsync(20_000);
    expect(m.callsTo('GET', SW).length).toBe(before);
  });
});

describe('error state', () => {
  it('shows a retry when the status cannot be loaded', async () => {
    mockFetch({ [`GET ${SW}`]: () => problem(503, 'not_ready'), 'GET /api/v1/admin/status': () => adminStatus() });
    renderWithApp(<StorageSwitch />, { role: 'admin' });
    expect(await screen.findByRole('button', { name: /try again/i })).toBeTruthy();
    expect(screen.getByText(/not ready/i)).toBeTruthy();
  });
});
