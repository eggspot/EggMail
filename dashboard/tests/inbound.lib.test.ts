import { describe, expect, it } from 'vitest';
import type { InboundSettings } from '../src/api/types';
import { safeFileName } from '../src/lib/download';
import {
  canRetry,
  describeAction,
  describeMatch,
  emptyRouteForm,
  explainActionCode,
  routeRequest,
  routeToForm,
  settingsPatch,
  settingsToForm,
  splitAddresses,
  validateRoute,
  validateSettings,
} from '../src/lib/inbound';

const settings: InboundSettings = {
  domainId: 'd1',
  enabled: false,
  dmarcAction: 'record_only',
  maxMessageBytes: null,
  maxMessagesPerMinute: null,
  maxMessagesPerMinutePerRemote: null,
  maxStoredBytes: null,
  retentionDays: null,
  updatedAt: null,
  effective: { maxMessageBytes: 26214400, maxMessagesPerMinute: 600, maxMessagesPerMinutePerRemote: 60, maxStoredBytes: 2147483648, retentionDays: 7 },
  mx: { host: 'mta.example.net', priority: 10 },
};

describe('inbound settings form', () => {
  it('starts empty for the server values and sends nothing when nothing changed', () => {
    const form = settingsToForm(settings);
    expect(form.maxMessageMiB).toBe('');
    expect(form.retentionDays).toBe('');
    expect(settingsPatch(settings, form)).toEqual({});
    expect(validateSettings(form)).toEqual({});
  });

  it('sends only the members that changed, so a lowered ceiling elsewhere never blocks the change', () => {
    const stored: InboundSettings = { ...settings, enabled: true, maxMessageBytes: 5 * 1024 * 1024, retentionDays: 30 };
    const form = { ...settingsToForm(stored), enabled: false };
    expect(settingsPatch(stored, form)).toEqual({ enabled: false });
    expect(settingsPatch(stored, { ...settingsToForm(stored), retentionDays: '' })).toEqual({ retentionDays: null });   // back to the server value
    expect(settingsPatch(stored, { ...settingsToForm(stored), maxMessageMiB: '2.5', dmarcAction: 'reject' })).toEqual({ maxMessageBytes: 2.5 * 1024 * 1024, dmarcAction: 'reject' });
  });

  it('treats 0 as unlimited for stored mail and forever for retention, and validates ranges', () => {
    const form = { ...settingsToForm(settings), maxStoredMiB: '0', retentionDays: '0' };
    expect(settingsPatch(settings, form)).toEqual({ maxStoredBytes: 0, retentionDays: 0 });
    expect(validateSettings(form)).toEqual({});
    const bad = validateSettings({ ...settingsToForm(settings), maxMessageMiB: 'abc', maxMessagesPerMinute: '0', maxMessagesPerMinutePerRemote: '10001', maxStoredMiB: '0.5', retentionDays: '-1' });
    expect(Object.keys(bad).sort()).toEqual(['maxMessageMiB', 'maxMessagesPerMinute', 'maxMessagesPerMinutePerRemote', 'maxStoredMiB', 'retentionDays']);
    expect(validateSettings({ ...settingsToForm(settings), maxMessageMiB: '2000' }).maxMessageMiB).toBeTruthy();
    expect(validateSettings({ ...settingsToForm(settings), retentionDays: '36501' }).retentionDays).toBeTruthy();
  });
});

describe('inbound route form', () => {
  it('validates the match like the server', () => {
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'address', localPart: '' }).localPart).toBeTruthy();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'address', localPart: 'a*b' }).localPart).toBeTruthy();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'address', localPart: 'a b' }).localPart).toBeTruthy();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'address', localPart: 'a@b' }).localPart).toBeTruthy();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'address', localPart: 'Support' }).localPart).toBeUndefined();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'wildcard', localPart: 'billing-*' }).localPart).toBeUndefined();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'wildcard', localPart: 'billing' }).localPart).toBeTruthy();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'wildcard', localPart: '***' }).localPart).toBeTruthy();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'wildcard', localPart: 'a*b*c*d*' }).localPart).toBeTruthy();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'catch_all', localPart: '' })).toEqual({});
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'catch_all', order: 'x' }).order).toBeTruthy();
  });

  it('validates the action: a webhook needs an endpoint, a forward needs one to ten distinct valid addresses', () => {
    const base = { ...emptyRouteForm, matchKind: 'catch_all' as const };
    expect(validateRoute({ ...base, actionKind: 'webhook' }).webhookEndpointId).toBeTruthy();
    expect(validateRoute({ ...base, actionKind: 'webhook', webhookEndpointId: 'w1' })).toEqual({});
    expect(validateRoute({ ...base, actionKind: 'forward', forwardTo: '' }).forwardTo).toBeTruthy();
    expect(validateRoute({ ...base, actionKind: 'forward', forwardTo: 'a@example.org\nnot-an-address' }).forwardTo).toContain('not-an-address');
    expect(validateRoute({ ...base, actionKind: 'forward', forwardTo: 'a@example.org, A@example.org' }).forwardTo).toBeTruthy();
    expect(validateRoute({ ...base, actionKind: 'forward', forwardTo: Array.from({ length: 11 }, (_, i) => `u${i}@example.org`).join('\n') }).forwardTo).toBeTruthy();
    expect(validateRoute({ ...base, actionKind: 'forward', forwardTo: 'a@example.org b@example.org' })).toEqual({});
    expect(splitAddresses('a@x.test, b@x.test;\n c@x.test')).toEqual(['a@x.test', 'b@x.test', 'c@x.test']);
  });

  it('builds a complete request: lower-case local part, only the members of the chosen kinds', () => {
    expect(routeRequest({ ...emptyRouteForm, name: ' Support ', order: ' 20 ', matchKind: 'address', localPart: 'Support', plusAddressing: true, actionKind: 'store' })).toEqual({
      name: 'Support',
      order: 20,
      enabled: true,
      match: { kind: 'address', localPart: 'support', plusAddressing: true },
      action: { kind: 'store' },
    });
    expect(routeRequest({ ...emptyRouteForm, matchKind: 'catch_all', localPart: 'ignored', actionKind: 'webhook', webhookEndpointId: 'w1', webhookFormat: 'raw_mime' })).toMatchObject({
      match: { kind: 'catch_all' },
      action: { kind: 'webhook', webhookEndpointId: 'w1', webhookFormat: 'raw_mime' },
    });
    const request = routeRequest({ ...emptyRouteForm, matchKind: 'catch_all', actionKind: 'forward', forwardTo: 'a@example.org\nb@example.org' });
    expect(request.match).toEqual({ kind: 'catch_all' });
    expect(request.action).toEqual({ kind: 'forward', forwardTo: ['a@example.org', 'b@example.org'] });
  });

  it('round-trips a stored route through the form', () => {
    const route = {
      id: 'r1', domainId: 'd1', name: 'n', order: 5, enabled: false, match: { kind: 'wildcard' as const, localPart: 'x-*', plusAddressing: true },
      action: { kind: 'forward' as const, forwardTo: ['a@example.org'] }, createdAt: '', updatedAt: '',
    };
    const form = routeToForm(route);
    expect(routeRequest(form)).toMatchObject({ name: 'n', order: 5, enabled: false, match: route.match, action: route.action });
    expect(describeMatch(route)).toContain('x-*');
    expect(describeAction(route)).toBe('forward to a@example.org');
  });
});

describe('inbound explanations', () => {
  it('explains the codes of the action in plain words and shows unknown ones as they are', () => {
    expect(explainActionCode('webhook_http_503')).toContain('503');
    expect(explainActionCode('endpoint_disabled')).toContain('Enable');
    expect(explainActionCode('route_is_now_store')).toContain('kept');
    expect(explainActionCode('unauthenticated_local_sender')).toContain('spoof');
    for (const code of ['forward_backlog_full', 'forward_key_conflict', 'dmarc_unsettled', 'srs_failed']) expect(explainActionCode(code)).toBeTruthy();
    expect(explainActionCode('something_new')).toBeNull();
    expect(explainActionCode(null)).toBeNull();
  });

  it('allows a retry only for webhook and forward actions that are not waiting and still have their message', () => {
    const base = { hasRaw: true, action: { kind: 'webhook' as const, state: 'failed' as const } };
    expect(canRetry(base)).toBe(true);
    expect(canRetry({ ...base, action: { ...base.action, state: 'pending' } })).toBe(false);
    expect(canRetry({ ...base, hasRaw: false })).toBe(false);
    expect(canRetry({ ...base, action: { kind: 'store', state: 'done' } })).toBe(false);
    expect(canRetry({ ...base, action: { kind: 'webhook', state: 'done', currentKind: 'discard' } })).toBe(false);   // the route does nothing with it now
  });

  it('cleans a file name before it is saved', () => {
    expect(safeFileName('../../etc/passwd')).toBe('passwd');
    expect(safeFileName('C:\\x\\evil<script>.html')).toBe('evil_script_.html');
    expect(safeFileName('.hidden')).toBe('hidden');
    expect(safeFileName('')).toBe('download');
    expect(safeFileName(null, 'attachment-0')).toBe('attachment-0');
    expect(safeFileName('x'.repeat(300)).length).toBe(100);
  });
});
