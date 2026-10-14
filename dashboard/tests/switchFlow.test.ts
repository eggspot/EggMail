import { describe, expect, it } from 'vitest';
import type { SwitchState } from '../src/api/types';
import {
  allowedActions,
  buildRequest,
  confirmationMatches,
  confirmationPhrase,
  defaultTarget,
  flowReducer,
  includeList,
  initialForm,
  initialLocal,
  isIdle,
  isRunning,
  stateText,
  STATE_LABEL,
  stepFor,
  stepIndex,
  validateForm,
  validatePassphrase,
} from '../src/lib/switchFlow';
import type { FlowLocal } from '../src/lib/switchFlow';

const ALL: SwitchState[] = ['none', 'draining', 'quiescing', 'fenced', 'exporting', 'importing', 'verifying', 'verified', 'confirmed', 'active', 'finalized', 'rolled_back', 'failed'];

describe('stepFor (server state to wizard step)', () => {
  const local = (step: FlowLocal['step']): FlowLocal => ({ step, preflightOk: true });

  it('follows the local step while no switch is in flight', () => {
    for (const s of ['choose', 'preflight', 'start'] as const) {
      expect(stepFor('none', local(s))).toBe(s);
      expect(stepFor('rolled_back', local(s))).toBe(s);
    }
  });

  it('maps every long-running state to progress', () => {
    for (const s of ['draining', 'quiescing', 'fenced', 'exporting', 'importing', 'verifying', 'failed'] as const) expect(stepFor(s, local('choose'))).toBe('progress');
    // A state this dashboard does not know (a newer server) is work in progress, never a blank page.
    expect(stepFor('something_new' as SwitchState, local('choose'))).toBe('progress');
  });

  it('maps verified, confirmed, active and finalized', () => {
    expect(stepFor('verified', local('choose'))).toBe('verify');
    expect(stepFor('confirmed', local('choose'))).toBe('activate');
    expect(stepFor('active', local('choose'))).toBe('finalize');
    expect(stepFor('finalized', local('choose'))).toBe('done');
  });

  it('server state wins over a stale local step once a switch exists', () => {
    expect(stepFor('verified', local('start'))).toBe('verify');
    expect(stepFor('active', local('preflight'))).toBe('finalize');
  });

  it('has an index for every step', () => {
    expect(stepIndex('choose')).toBe(0);
    expect(stepIndex('finalize')).toBe(6);
    expect(stepIndex('done')).toBe(7);
  });
});

describe('allowedActions', () => {
  it('allows start only when no switch is in flight', () => {
    for (const s of ALL) expect(allowedActions(s, true).start).toBe(['none', 'rolled_back', 'finalized'].includes(s));
  });

  it('allows rollback only before activation', () => {
    const allowed = ['draining', 'quiescing', 'fenced', 'exporting', 'importing', 'verifying', 'verified', 'confirmed', 'failed'];
    for (const s of ALL) expect(allowedActions(s, true).rollback).toBe(allowed.includes(s));
    expect(allowedActions('active', true).rollback).toBe(false);
    expect(allowedActions('finalized', true).rollback).toBe(false);
  });

  it('after activation only the reverse switch is offered', () => {
    expect(allowedActions('active', true).reverseSwitchOnly).toBe(true);
    expect(allowedActions('confirmed', true).reverseSwitchOnly).toBe(false);
  });

  it('allows finalize only from active', () => {
    for (const s of ALL) expect(allowedActions(s, true).finalize).toBe(s === 'active');
  });

  it('allows confirm only from verified with a passing report', () => {
    expect(allowedActions('verified', true).confirm).toBe(true);
    expect(allowedActions('verified', false).confirm).toBe(false);
    expect(allowedActions('verified', undefined).confirm).toBe(false);
    for (const s of ALL.filter((x) => x !== 'verified')) expect(allowedActions(s, true).confirm).toBe(false);
  });

  it('allows activate only from confirmed', () => {
    for (const s of ALL) expect(allowedActions(s, true).activate).toBe(s === 'confirmed');
  });

  it('classifies running and idle states without overlap', () => {
    for (const s of ALL) expect(isRunning(s) && isIdle(s)).toBe(false);
    expect(isRunning('exporting')).toBe(true);
    expect(isRunning('verified')).toBe(false);
    expect(isIdle('none')).toBe(true);
  });

  it('has text for every state', () => {
    for (const s of ALL) {
      expect(stateText(s).length).toBeGreaterThan(10);
      expect(STATE_LABEL[s]).toBeTruthy();
    }
  });
});

describe('flowReducer (local steps)', () => {
  it('moves choose -> preflight -> start with a passing preflight', () => {
    let s = flowReducer(initialLocal, { type: 'preflight-done', ok: true });
    expect(s).toEqual({ step: 'preflight', preflightOk: true });
    s = flowReducer(s, { type: 'proceed' });
    expect(s.step).toBe('start');
  });

  it('refuses to proceed after a failed preflight', () => {
    const s = flowReducer(initialLocal, { type: 'preflight-done', ok: false });
    expect(s.step).toBe('preflight');
    expect(flowReducer(s, { type: 'proceed' })).toBe(s);
  });

  it('ignores illegal transitions', () => {
    expect(flowReducer(initialLocal, { type: 'proceed' })).toBe(initialLocal);
    expect(flowReducer(initialLocal, { type: 'back' })).toBe(initialLocal);
    const start: FlowLocal = { step: 'start', preflightOk: true };
    expect(flowReducer(start, { type: 'preflight-done', ok: true })).toBe(start);
    expect(flowReducer(start, { type: 'proceed' })).toBe(start);
  });

  it('goes back one step at a time and resets', () => {
    const start: FlowLocal = { step: 'start', preflightOk: true };
    const pre = flowReducer(start, { type: 'back' });
    expect(pre.step).toBe('preflight');
    expect(flowReducer(pre, { type: 'back' }).step).toBe('choose');
    expect(flowReducer(start, { type: 'reset' })).toEqual(initialLocal);
  });
});

describe('form helpers', () => {
  it('defaults to the opposite backend (symmetric switching)', () => {
    expect(defaultTarget('sqlite')).toBe('postgres');
    expect(defaultTarget('postgres')).toBe('sqlite');
    expect(initialForm('sqlite').to).toBe('postgres');
    expect(initialForm('postgres').to).toBe('sqlite');
  });

  it('only includes queued mail with quiesce', () => {
    const f = { ...initialForm('sqlite'), includeQueue: true, includeHistory: true };
    expect(includeList({ ...f, mode: 'drain' })).toEqual(['history']);
    expect(includeList({ ...f, mode: 'quiesce' })).toEqual(['queue', 'history']);
    expect(includeList({ ...f, mode: 'quiesce', includeHistory: false })).toEqual(['queue']);
  });

  it('builds postgres and sqlite targets', () => {
    const pg = { ...initialForm('sqlite'), host: ' db.internal ', database: 'eggmail', port: '5433' };
    expect(buildRequest(pg)).toEqual({ to: 'postgres', mode: 'drain', include: ['history'], target: { host: 'db.internal', port: 5433, database: 'eggmail' } });
    expect(buildRequest({ ...pg, connectionName: 'main-pg' }).target).toEqual({ connectionName: 'main-pg' });
    const lite = { ...initialForm('postgres'), path: ' /data ' };
    expect(buildRequest(lite).target).toEqual({ path: '/data' });
  });

  it('validates targets', () => {
    expect(validateForm(initialForm('sqlite'))).toEqual({ host: expect.any(String), database: expect.any(String) });
    expect(validateForm({ ...initialForm('sqlite'), host: 'h', database: 'd' })).toEqual({});
    expect(validateForm({ ...initialForm('sqlite'), connectionName: 'x' })).toEqual({});
    expect(validateForm({ ...initialForm('sqlite'), host: 'h', database: 'd', port: '99999' }).port).toBeTruthy();
    expect(validateForm({ ...initialForm('postgres'), path: '  ' }).path).toBeTruthy();
  });

  it('validates the passphrase length and repetition', () => {
    expect(validatePassphrase('short', 'short').passphrase).toBeTruthy();
    expect(validatePassphrase('a-long-enough-pass', 'different-long-pass').repeat).toBeTruthy();
    expect(validatePassphrase('a-long-enough-pass', 'a-long-enough-pass')).toEqual({});
  });

  it('requires the exact typed confirmation', () => {
    expect(confirmationPhrase('postgres')).toBe('switch to postgres');
    expect(confirmationMatches('postgres', ' switch to postgres ')).toBe(true);
    expect(confirmationMatches('postgres', 'switch to sqlite')).toBe(false);
    expect(confirmationMatches('sqlite', 'Switch to sqlite')).toBe(false);
  });
});
