import { describe, expect, it } from 'vitest';
import type { InboundSettings } from '../src/api/types';
import { buildSrcDoc, removeHeadTags } from '../src/components/MessageHtmlFrame';
import { emptyRouteForm, settingsPatch, settingsToForm, validateRoute, validateSettings } from '../src/lib/inbound';

const settings = (over: Partial<InboundSettings> = {}): InboundSettings => ({
  domainId: 'd1', enabled: true, dmarcAction: 'record_only', maxMessageBytes: null, maxMessagesPerMinute: null, maxMessagesPerMinutePerRemote: null, maxStoredBytes: null, retentionDays: null,
  updatedAt: null,
  effective: { maxMessageBytes: 26214400, maxMessagesPerMinute: 600, maxMessagesPerMinutePerRemote: 60, maxStoredBytes: 2147483648, retentionDays: 7 },
  mx: { host: 'mta.example.net', priority: 10 },
  ...over,
});

describe('a value the tenant did not touch is never written back rounded', () => {
  it.each([25_000_000, 1024, 1536, 10_485_761, 1_073_741_823, 5 * 1024 * 1024])('%i bytes survive a save that changes something else', (bytes) => {
    const stored = settings({ maxMessageBytes: bytes, maxStoredBytes: bytes === 1024 ? 1048576 : bytes + 1000 });
    const form = { ...settingsToForm(stored), enabled: false };
    expect(settingsPatch(stored, form)).toEqual({ enabled: false });
  });

  it('shows a small size as a small number and sends exactly what the tenant types', () => {
    expect(settingsToForm(settings({ maxMessageBytes: 1024 })).maxMessageMiB).toBe('0.000977');
    expect(settingsToForm(settings({ maxMessageBytes: 25_000_000 })).maxMessageMiB).toBe('23.841858');
    const stored = settings({ maxMessageBytes: 25_000_000 });
    expect(settingsPatch(stored, { ...settingsToForm(stored), maxMessageMiB: '20' })).toEqual({ maxMessageBytes: 20 * 1024 * 1024 });
    expect(settingsPatch(stored, { ...settingsToForm(stored), maxMessageMiB: '' })).toEqual({ maxMessageBytes: null });
    expect(validateSettings({ ...settingsToForm(settings({ maxMessageBytes: 1024 })) })).toEqual({});
  });

  it('does not send a number whose text is only written differently', () => {
    const stored = settings({ maxMessagesPerMinute: 60, retentionDays: 30 });
    expect(settingsPatch(stored, { ...settingsToForm(stored), maxMessagesPerMinute: ' 60 ' })).toEqual({});
  });
});

describe('route form parity with the server', () => {
  it('order is a whole number from 0 to 1000000, the name has no control characters', () => {
    const catchAll = { ...emptyRouteForm, matchKind: 'catch_all' as const };
    expect(validateRoute({ ...catchAll, order: '0' })).toEqual({});
    expect(validateRoute({ ...catchAll, order: '1000000' })).toEqual({});
    expect(validateRoute({ ...catchAll, order: '1000001' }).order).toBeTruthy();
    expect(validateRoute({ ...catchAll, order: '-1' }).order).toBeTruthy();
    expect(validateRoute({ ...catchAll, name: 'bell\u0007' }).name).toBeTruthy();
    expect(validateRoute({ ...catchAll, name: 'line\nbreak' }).name).toBeTruthy();
    expect(validateRoute({ ...catchAll, name: 'Rechnungen über 100' })).toEqual({});
  });

  it('accepts an internationalized local part in a match, like the server', () => {
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'address' as const, localPart: 'josé' }).localPart).toBeUndefined();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'wildcard' as const, localPart: 'rechnung-*-ü' }).localPart).toBeUndefined();
    expect(validateRoute({ ...emptyRouteForm, matchKind: 'address' as const, localPart: 'a b' }).localPart).toBeTruthy();
  });

  it('accepts internationalized forward addresses', () => {
    const forward = { ...emptyRouteForm, matchKind: 'catch_all' as const, actionKind: 'forward' as const };
    expect(validateRoute({ ...forward, forwardTo: 'jürgen@bücher.example' })).toEqual({});
    expect(validateRoute({ ...forward, forwardTo: '用户@例え.テスト' })).toEqual({});
    expect(validateRoute({ ...forward, forwardTo: 'plain@example.org' })).toEqual({});
    expect(validateRoute({ ...forward, forwardTo: 'no-domain@' }).forwardTo).toBeTruthy();
    expect(validateRoute({ ...forward, forwardTo: 'a@b' }).forwardTo).toBeTruthy();
  });
});

describe('the sandboxed frame gets no head tags from the message', () => {
  it.each([
    '<meta http-equiv="refresh" content="0;url=https://evil.invalid">',
    '<META HTTP-EQUIV=refresh CONTENT="0;url=https://evil.invalid">',
    '<meta http-equiv="refresh" content="0;url=https://evil.invalid/?a>b">',
    "<meta http-equiv='refresh' content='0;url=https://evil.invalid/?a>b'>",
    '<meta\nhttp-equiv\n=\n"refresh"\ncontent="0;url=https://evil.invalid">',
    '<base href="https://evil.invalid/">',
    '<base href="x>y" target=_top>',
    '<link rel=stylesheet href="https://evil.invalid/x.css">',
    '<meta http-equiv="refresh" content="0;url=https://evil.invalid',
    '<meta/http-equiv="refresh" content="0;url=https://evil.invalid">',
  ])('%s', (tag) => {
    const doc = buildSrcDoc(`before${tag}after`);
    const body = doc.slice(doc.indexOf('</head><body>') + '</head><body>'.length);
    expect(body).not.toMatch(/<\s*(meta|base|link)(?![A-Za-z0-9-])/i);
    expect(doc.match(/<meta\b/gi)?.length).toBe(3);   // only the frame's own: charset, policy and referrer
  });

  it('keeps the policy first and the rest of the message intact', () => {
    const doc = buildSrcDoc('<p>hello</p><metadata>x</metadata>');
    expect(doc.indexOf('Content-Security-Policy')).toBeLessThan(doc.indexOf('<p>hello</p>'));
    expect(removeHeadTags('<p>a</p><metadata>x</metadata>')).toBe('<p>a</p><metadata>x</metadata>');   // other tags that merely start with the letters stay
  });

  it('stays linear on hostile input: 256 KiB of unterminated tags (the most the server returns)', () => {
    for (const unit of ['<meta ', '<base "', "<link a='x' "]) {
      const html = unit.repeat(Math.ceil((256 * 1024) / unit.length));
      const started = performance.now();
      const out = removeHeadTags(html);
      expect(performance.now() - started).toBeLessThan(500);   // the per-start regex took about 10 s here
      expect(out).not.toMatch(/<\s*(meta|base|link)(?![A-Za-z0-9-])/i);
    }
  });

  it('removes closed tags and neutralizes a tag that never closes, and every start after it', () => {
    expect(removeHeadTags('a<meta x="1>2">b<base href=y>c')).toBe('abc');
    expect(removeHeadTags('a<meta x="never closed <link rel=x> b')).toBe('a&lt;meta x="never closed &lt;link rel=x> b');
    expect(removeHeadTags('<<meta>meta http-equiv=refresh>')).toBe('&lt;meta http-equiv=refresh>');   // removing one tag cannot assemble another
  });
});
