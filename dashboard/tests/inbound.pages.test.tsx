import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import DomainInbound from '../src/pages/DomainInbound';
import InboundMessageDetail from '../src/pages/InboundMessageDetail';
import InboundMessages from '../src/pages/InboundMessages';
import { Layout, NAV_ITEMS } from '../src/components/Layout';
import type { Domain, InboundMessageDetail as Detail, InboundMessageSummary, InboundRoute, InboundSettings } from '../src/api/types';
import { json, makeCapabilities, mockFetch, problem, renderWithApp } from './helpers';
import type { RecordedCall } from './helpers';

const on = { capabilities: makeCapabilities({ inbound: { enabled: true } }) };

const auth = {
  spf: { result: 'pass', domain: 'sender.test' },
  spfHelo: { result: 'none' },
  dkim: { result: 'pass', domain: 'sender.test' },
  dmarc: { result: 'fail', policy: 'reject' },
  arc: { result: 'none' },
} as const;

const summary = (over: Partial<InboundMessageSummary> = {}): InboundMessageSummary => ({
  id: 'm1', domainId: 'd1', domain: 'example.com', receivedAt: '2026-10-16T08:00:00.000Z', remoteIp: '203.0.113.9', helo: 'mail.sender.test', tls: true,
  from: 'alice@sender.test', to: 'support@example.com', subject: 'Hello', size: 2048, auth: { ...auth }, dmarcFlagged: false, routeId: 'r1',
  action: { kind: 'store', state: 'done', attempts: 0, retryGeneration: 0, nextAttemptAt: null, finishedAt: null, lastError: null, forwardMessageId: null },
  hasRaw: true, ...over,
});

const detail = (over: Partial<Detail> = {}): Detail => ({
  ...summary(),
  content: {
    state: 'available',
    headers: [{ name: 'Subject', value: 'Hello' }, { name: 'From', value: 'Alice <alice@sender.test>' }],
    text: 'Hi there',
    html: '<p>Hi <b>there</b></p>',
    truncated: false,
    attachments: [{ index: 0, filename: 'report.pdf', content_type: 'application/pdf', size: 12345, content_id: null, disposition: 'attachment' }],
  },
  ...over,
});

const domain: Domain = { id: 'd1', name: 'example.com', status: 'verified' } as Domain;

const settings = (over: Partial<InboundSettings> = {}): InboundSettings => ({
  domainId: 'd1', enabled: false, dmarcAction: 'record_only', maxMessageBytes: null, maxMessagesPerMinute: null, maxMessagesPerMinutePerRemote: null, maxStoredBytes: null, retentionDays: null,
  updatedAt: null,
  effective: { maxMessageBytes: 26214400, maxMessagesPerMinute: 600, maxMessagesPerMinutePerRemote: 60, maxStoredBytes: 2147483648, retentionDays: 7 },
  mx: { host: 'mta.example.net', priority: 10 },
  ...over,
});

const route = (over: Partial<InboundRoute> = {}): InboundRoute => ({
  id: 'r1', domainId: 'd1', name: 'Support', order: 10, enabled: true, match: { kind: 'address', localPart: 'support', plusAddressing: false },
  action: { kind: 'store' }, createdAt: '2026-10-16T08:00:00.000Z', updatedAt: '2026-10-16T08:00:00.000Z', ...over,
});

describe('inbound navigation', () => {
  it('shows the inbound page only while the server accepts inbound mail', () => {
    mockFetch({});
    expect(NAV_ITEMS.find((i) => i.href === '/inbound')?.inbound).toBe(true);
    const { unmount } = renderWithApp(<Layout><p>x</p></Layout>);
    expect(screen.queryByRole('link', { name: 'Inbound mail' })).toBeNull();
    unmount();
    renderWithApp(<Layout><p>x</p></Layout>, on);
    expect(screen.getByRole('link', { name: 'Inbound mail' })).toBeTruthy();
  });

  it('says so on the list page when the server does not accept inbound mail', () => {
    mockFetch({});
    renderWithApp(<InboundMessages />);
    expect(screen.getByText('Inbound mail is not enabled on this server')).toBeTruthy();
  });
});

describe('Inbound messages page', () => {
  const routes = (items: InboundMessageSummary[], next: string | null = null) => ({
    'GET /api/v1/inbound/usage': { messages: 12, bodyBytes: 1048576, pending: 2, failed: 1, oldestPendingAt: null },
    'GET /api/v1/domains': [domain],
    'GET /api/v1/inbound/messages': { items, next_cursor: next },
  });

  it('lists the newest messages with their checks and action, and shows the usage', async () => {
    mockFetch(routes([summary({ dmarcFlagged: true }), summary({ id: 'm2', subject: null, from: '', action: { kind: 'webhook', state: 'failed', attempts: 8, retryGeneration: 0, nextAttemptAt: null, finishedAt: null, lastError: 'webhook_http_500', forwardMessageId: null } })]));
    renderWithApp(<InboundMessages />, on);
    expect(await screen.findByRole('link', { name: 'Hello' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Hello' }).getAttribute('href')).toBe('/inbound/messages/m1');
    expect(screen.getByText('DMARC flagged')).toBeTruthy();
    expect(screen.getByText('(no subject)')).toBeTruthy();
    expect(screen.getByText('(bounce)')).toBeTruthy();
    expect(screen.getAllByText('SPF pass').length).toBeGreaterThan(0);
    expect(screen.getAllByText('DMARC fail').length).toBeGreaterThan(0);
    expect(screen.getByText('Webhook: failed')).toBeTruthy();
    const usage = await screen.findByTestId('inbound-usage');
    expect(within(usage).getByText('12')).toBeTruthy();
    expect(within(usage).getByText('1.0 MiB')).toBeTruthy();
  });

  it('renders hostile text as text, never as markup', async () => {
    mockFetch(routes([summary({ subject: '<img src=x onerror=alert(1)>', from: '"><script>alert(2)</script>@x.test', to: '<b>bold</b>@example.com' })]));
    const { container } = renderWithApp(<InboundMessages />, on);
    await screen.findByText('<img src=x onerror=alert(1)>');
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
  });

  it('shows an empty state, and searches with the filters and loads more pages', async () => {
    const m = mockFetch({
      ...routes([]),
      'GET /api/v1/inbound/messages': (c: RecordedCall) => (c.query.get('cursor') ? { items: [summary({ id: 'm9', subject: 'Second page' })], next_cursor: null } : { items: [summary()], next_cursor: 'c1' }),
    });
    renderWithApp(<InboundMessages />, on);
    await screen.findByRole('link', { name: 'Hello' });
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByRole('link', { name: 'Second page' })).toBeTruthy();

    fireEvent.input(screen.getByLabelText('Recipient'), { target: { value: 'support@example.com' } });
    fireEvent.input(screen.getByLabelText('Subject contains'), { target: { value: 'invoice' } });
    fireEvent.change(screen.getByLabelText('Action'), { target: { value: 'webhook' } });
    fireEvent.change(screen.getByLabelText('Action state'), { target: { value: 'failed' } });
    fireEvent.change(screen.getByLabelText('DMARC'), { target: { value: 'fail' } });
    fireEvent.click(screen.getByLabelText('Only messages flagged for failing DMARC'));
    fireEvent.click(screen.getByRole('button', { name: 'Search' }));
    await waitFor(() => {
      const last = m.callsTo('GET', '/api/v1/inbound/messages').at(-1)!;
      expect(last.query.get('recipient')).toBe('support@example.com');
      expect(last.query.get('subject')).toBe('invoice');
      expect(last.query.get('action')).toBe('webhook');
      expect(last.query.get('state')).toBe('failed');
      expect(last.query.get('dmarc')).toBe('fail');
      expect(last.query.get('dmarcFlagged')).toBe('true');
      expect(last.query.get('limit')).toBe('25');
    });
  });

  it('shows the empty state of a fresh install', async () => {
    mockFetch(routes([]));
    renderWithApp(<InboundMessages />, on);
    expect(await screen.findByText('No received messages')).toBeTruthy();
  });

  it('offers deleting the matches only with a filter, and only after typing the word', async () => {
    const m = mockFetch({ ...routes([summary()]), 'DELETE /api/v1/inbound/messages': { deleted: 3 } });
    renderWithApp(<InboundMessages />, on);
    await screen.findByRole('link', { name: 'Hello' });
    expect(screen.queryByRole('button', { name: 'Delete matching messages' })).toBeNull();   // nothing filtered: no way to empty the tenant by accident

    fireEvent.input(screen.getByLabelText('Sender'), { target: { value: 'alice@sender.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Delete matching messages' }));
    const confirm = screen.getByRole('button', { name: 'Delete messages' });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(screen.getByLabelText('Type "delete" to confirm'), { target: { value: 'delete' } });
    fireEvent.click(confirm);
    expect(await screen.findByText('3 messages were deleted.')).toBeTruthy();
    const call = m.callsTo('DELETE', '/api/v1/inbound/messages')[0];
    expect(call.query.get('sender')).toBe('alice@sender.test');
    expect(call.query.get('limit')).toBeNull();
  });
});

describe('Inbound message page', () => {
  let click: ReturnType<typeof vi.spyOn>;
  let clicked: HTMLAnchorElement[];
  beforeEach(() => {
    URL.createObjectURL = vi.fn(() => 'blob:x');
    URL.revokeObjectURL = vi.fn();
    clicked = [];
    click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this);
    });
  });
  afterEach(() => click.mockRestore());

  it('shows the envelope, the checks, the action and the content', async () => {
    mockFetch({ 'GET /api/v1/inbound/messages/m1': detail({ dmarcFlagged: true }) });
    renderWithApp(<InboundMessageDetail id="m1" />, on);
    expect(await screen.findByRole('heading', { name: 'Hello' })).toBeTruthy();
    expect(screen.getByText('Flagged: failed the sender\'s DMARC policy')).toBeTruthy();
    expect(screen.getByText('alice@sender.test')).toBeTruthy();
    expect(screen.getByText('203.0.113.9 (said mail.sender.test)')).toBeTruthy();
    expect(screen.getByText(/the sender's policy: reject/)).toBeTruthy();
    expect(screen.getByTestId('text-view').textContent).toBe('Hi there');
  });

  it('renders the HTML only in a sandboxed frame and hostile text as text', async () => {
    const hostile = '<script>alert(1)</script><img src="https://tracker.test/p.gif">';
    mockFetch({ 'GET /api/v1/inbound/messages/m1': detail({ subject: '<svg onload=alert(1)>', content: { ...detail().content, text: '<b>not bold</b>', html: hostile } }) });
    const { container } = renderWithApp(<InboundMessageDetail id="m1" />, on);
    await screen.findByTestId('text-view');
    expect(container.querySelector('svg')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    expect(screen.getByTestId('text-view').textContent).toBe('<b>not bold</b>');
    fireEvent.click(screen.getByRole('tab', { name: 'HTML (sandboxed)' }));
    const frame = container.querySelector('iframe')!;
    expect(frame.getAttribute('sandbox')).toBe('');   // the empty sandbox: no scripts, forms, popups or navigation
    expect(frame.getAttribute('srcdoc')).toContain("default-src 'none'");
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
  });

  it('lists the headers and downloads an attachment as a file instead of opening it', async () => {
    const m = mockFetch({
      'GET /api/v1/inbound/messages/m1': detail(),
      'GET /api/v1/inbound/messages/m1/attachments/0': () => new Response('%PDF', { status: 200, headers: { 'Content-Type': 'application/octet-stream' } }),
    });
    renderWithApp(<InboundMessageDetail id="m1" />, on);
    await screen.findByTestId('text-view');
    fireEvent.click(screen.getByRole('tab', { name: 'Headers (2)' }));
    expect(screen.getByText('Alice <alice@sender.test>')).toBeTruthy();
    fireEvent.click(screen.getByRole('tab', { name: 'Attachments (1)' }));
    fireEvent.click(screen.getByRole('button', { name: 'Download report.pdf' }));
    await waitFor(() => expect(clicked).toHaveLength(1));
    expect(m.callsTo('GET', '/api/v1/inbound/messages/m1/attachments/0')).toHaveLength(1);
    expect(URL.createObjectURL).toHaveBeenCalled();
    expect(clicked[0].download).toBe('report.pdf');
  });

  it('downloads the whole message', async () => {
    const calls = mockFetch({ 'GET /api/v1/inbound/messages/m1': detail(), 'GET /api/v1/inbound/messages/m1/raw': () => new Response('From: x', { status: 200 }) });
    renderWithApp(<InboundMessageDetail id="m1" />, on);
    fireEvent.click(await screen.findByRole('button', { name: 'Download message (.eml)' }));
    await waitFor(() => expect(clicked).toHaveLength(1));
    expect(calls.callsTo('GET', '/api/v1/inbound/messages/m1/raw')).toHaveLength(1);
    expect(clicked[0].download).toBe('m1.eml');
  });

  it('explains a failed action and retries it', async () => {
    const failed = detail({ action: { kind: 'webhook', state: 'failed', attempts: 8, retryGeneration: 0, nextAttemptAt: null, finishedAt: '2026-10-17T10:00:00.000Z', lastError: 'webhook_http_503', forwardMessageId: null, currentKind: 'webhook' } });
    const m = mockFetch({ 'GET /api/v1/inbound/messages/m1': failed, 'POST /api/v1/inbound/messages/m1/retry': { id: 'm1', action: { state: 'pending' } } });
    renderWithApp(<InboundMessageDetail id="m1" />, on);
    expect(await screen.findByText('The action failed')).toBeTruthy();
    expect(screen.getByText('The receiver answered HTTP 503.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Retry the action' }));
    await waitFor(() => expect(m.callsTo('POST', '/api/v1/inbound/messages/m1/retry')).toHaveLength(1));
    await waitFor(() => expect(m.callsTo('GET', '/api/v1/inbound/messages/m1').length).toBeGreaterThan(1));   // reloaded
  });

  it('says when the route changed after arrival and when the copy is gone; no retry then', async () => {
    mockFetch({
      'GET /api/v1/inbound/messages/m1': detail({
        hasRaw: false,
        action: { kind: 'forward', state: 'done', attempts: 1, retryGeneration: 0, nextAttemptAt: null, finishedAt: '2026-10-16T09:00:00.000Z', lastError: null, forwardMessageId: 'f1', currentKind: 'store', note: 'route_is_now_store' },
        content: { state: 'no_body', headers: [], truncated: false, attachments: [] },
      }),
    });
    renderWithApp(<InboundMessageDetail id="m1" />, on);
    expect(await screen.findByText(/The route was changed after this message arrived/)).toBeTruthy();
    expect(screen.getByText(/route was changed to "store"/)).toBeTruthy();
    expect(screen.getByRole('link', { name: 'open the outbound message' }).getAttribute('href')).toBe('/messages/f1');
    expect(screen.getByText('The message itself is not kept')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Retry the action' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Download message (.eml)' })).toBeNull();
  });

  it('deletes after confirmation', async () => {
    const m = mockFetch({ 'GET /api/v1/inbound/messages/m1': detail(), 'DELETE /api/v1/inbound/messages/m1': undefined });
    renderWithApp(<InboundMessageDetail id="m1" />, on);
    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete message' }));
    await waitFor(() => expect(m.callsTo('DELETE', '/api/v1/inbound/messages/m1')).toHaveLength(1));
  });

  it('answers a message that is gone', async () => {
    mockFetch({ 'GET /api/v1/inbound/messages/m1': () => problem(404, 'not_found') });
    renderWithApp(<InboundMessageDetail id="m1" />, on);
    expect(await screen.findByText('Message not found')).toBeTruthy();
  });
});

describe('Domain inbound page', () => {
  const base = (over: Record<string, unknown> = {}) => ({
    'GET /api/v1/domains/d1': domain,
    'GET /api/v1/domains/d1/inbound': settings(),
    'GET /api/v1/domains/d1/inbound/routes': [route()],
    'GET /api/v1/webhooks': [{ id: 'w1', url: 'https://hooks.example/a', event_types: ['*'], enabled: true }, { id: 'w2', url: 'https://old.example/b', event_types: ['*'], enabled: false }],
    ...over,
  });

  it('shows the settings with the values that apply, and the MX to publish', async () => {
    mockFetch(base());
    renderWithApp(<DomainInbound id="d1" />, on);
    expect(await screen.findByRole('heading', { name: 'Inbound mail: example.com' })).toBeTruthy();
    expect((screen.getByLabelText('Keep received mail (days)') as HTMLInputElement).placeholder).toBe('7');
    expect(screen.getByText(/Empty: the server value \(7 days\)/)).toBeTruthy();
    expect(screen.getByTestId('mx-host').textContent).toBe('example.com');
    expect(screen.getByTestId('mx-value').textContent).toBe('10 mta.example.net');
    expect(screen.getByText(/port 25 must be reachable/)).toBeTruthy();
    expect(screen.getByText(/MTA-STS or TLS-RPT/)).toBeTruthy();
    expect(screen.getByText('Off')).toBeTruthy();
  });

  it('sends only what changed when saving, and shows what the server answered', async () => {
    const m = mockFetch(base({ 'PATCH /api/v1/domains/d1/inbound': (c: RecordedCall) => json(settings({ enabled: true, dmarcAction: 'flag', retentionDays: 30, ...(c.body as object) })) }));
    renderWithApp(<InboundMessageDetailPlaceholder />, on);
    expect(await screen.findByRole('heading', { name: 'Inbound mail: example.com' })).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Save settings' }) as HTMLButtonElement).disabled).toBe(true);   // nothing changed
    fireEvent.click(screen.getByLabelText('Receive mail for this domain'));
    fireEvent.change(screen.getByLabelText('When a message fails DMARC'), { target: { value: 'flag' } });
    fireEvent.input(screen.getByLabelText('Keep received mail (days)'), { target: { value: '30' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('Settings saved.')).toBeTruthy();
    expect(m.callsTo('PATCH', '/api/v1/domains/d1/inbound')[0].body).toEqual({ enabled: true, dmarcAction: 'flag', retentionDays: 30 });
    expect(screen.getByText('Receiving')).toBeTruthy();
  });

  it('checks the limits before sending and warns about keeping mail forever', async () => {
    const m = mockFetch(base());
    renderWithApp(<DomainInbound id="d1" />, on);
    await screen.findByRole('heading', { name: 'Inbound mail: example.com' });
    fireEvent.input(screen.getByLabelText('Messages per minute'), { target: { value: '0' } });
    fireEvent.input(screen.getByLabelText('Keep received mail (days)'), { target: { value: '0' } });
    expect(screen.getByText('Messages are kept forever')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('Enter a whole number from 1 to 100000, or leave it empty.')).toBeTruthy();
    expect(m.callsTo('PATCH', '/api/v1/domains/d1/inbound')).toHaveLength(0);
  });

  it('shows the server\'s answer when the domain is not verified or a ceiling is exceeded', async () => {
    mockFetch(base({
      'PATCH /api/v1/domains/d1/inbound': () => problem(400, 'validation_failed', { errors: [{ field: 'maxMessageBytes', message: 'At most 26214400 bytes on this server (Inbound:MaxMessageSize).' }] }),
    }));
    renderWithApp(<DomainInbound id="d1" />, on);
    await screen.findByRole('heading', { name: 'Inbound mail: example.com' });
    fireEvent.input(screen.getByLabelText('Largest message (MiB)'), { target: { value: '100' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('At most 26214400 bytes on this server (Inbound:MaxMessageSize).')).toBeTruthy();
  });

  it('warns that an unverified domain cannot receive, and that the server may be off', async () => {
    mockFetch(base({ 'GET /api/v1/domains/d1': { ...domain, status: 'pending' } }));
    renderWithApp(<DomainInbound id="d1" />);   // capabilities say inbound is off
    expect(await screen.findByText('The domain is not verified')).toBeTruthy();
    expect(screen.getByText('Inbound mail is not enabled on this server')).toBeTruthy();
  });

  it('lists the routes in order and adds a webhook route', async () => {
    const m = mockFetch(base({
      'GET /api/v1/domains/d1/inbound/routes': [route({ id: 'r2', name: 'Everything', order: 1000, match: { kind: 'catch_all' } }), route()],
      'POST /api/v1/domains/d1/inbound/routes': (c: RecordedCall) => json({ ...route({ id: 'r3' }), ...(c.body as object) }, 201),
    }));
    renderWithApp(<DomainInbound id="d1" />, on);
    await screen.findByRole('heading', { name: 'Inbound mail: example.com' });
    await screen.findByText('Everything');
    const rows = screen.getAllByRole('row').map((r) => r.textContent ?? '');
    const support = rows.findIndex((t) => t.includes('Support'));
    const everything = rows.findIndex((t) => t.includes('Everything'));
    expect(support).toBeGreaterThan(0);
    expect(support).toBeLessThan(everything);   // order 10 before order 1000, whatever the server's order

    fireEvent.click(screen.getByRole('button', { name: 'Add route' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.input(within(dialog).getByLabelText('Address (before the @)'), { target: { value: 'Billing' } });
    fireEvent.change(within(dialog).getByLabelText('Then'), { target: { value: 'webhook' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add route' }));
    expect(await within(dialog).findByText(/Choose a webhook endpoint/)).toBeTruthy();   // validated before the request
    expect(m.callsTo('POST', '/api/v1/domains/d1/inbound/routes')).toHaveLength(0);
    fireEvent.change(within(dialog).getByLabelText('Webhook endpoint'), { target: { value: 'w1' } });
    fireEvent.change(within(dialog).getByLabelText('Format'), { target: { value: 'raw_mime' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add route' }));
    await waitFor(() => expect(m.callsTo('POST', '/api/v1/domains/d1/inbound/routes')).toHaveLength(1));
    expect(m.callsTo('POST', '/api/v1/domains/d1/inbound/routes')[0].body).toEqual({
      name: '', order: 100, enabled: true,
      match: { kind: 'address', localPart: 'billing', plusAddressing: false },
      action: { kind: 'webhook', webhookEndpointId: 'w1', webhookFormat: 'raw_mime' },
    });
  });

  it('adds a forward route and shows the warning the server attaches', async () => {
    mockFetch(base({
      'GET /api/v1/domains/d1/inbound/routes': [],
      'POST /api/v1/domains/d1/inbound/routes': (c: RecordedCall) => json({ ...route({ id: 'r3' }), ...(c.body as object), warnings: [{ code: 'spf_not_ok', message: 'SPF at the final receiver will not pass.' }] }, 201),
    }));
    renderWithApp(<DomainInbound id="d1" />, on);
    expect(await screen.findByText('No routes yet')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Add route' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Matches'), { target: { value: 'catch_all' } });
    fireEvent.change(within(dialog).getByLabelText('Then'), { target: { value: 'forward' } });
    fireEvent.input(within(dialog).getByLabelText('Forward to'), { target: { value: 'me@elsewhere.test\nnot an address' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add route' }));
    expect(await within(dialog).findByText(/is not a valid address/)).toBeTruthy();
    fireEvent.input(within(dialog).getByLabelText('Forward to'), { target: { value: 'me@elsewhere.test' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add route' }));
    expect(await screen.findByText('SPF at the final receiver will not pass.')).toBeTruthy();
  });

  it('shows a server-side field error next to the field', async () => {
    mockFetch(base({
      'POST /api/v1/domains/d1/inbound/routes': () => problem(400, 'validation_failed', { errors: [{ field: 'action.forwardTo[0]', message: 'A forward there would loop.' }] }),
    }));
    renderWithApp(<DomainInbound id="d1" />, on);
    await screen.findByRole('heading', { name: 'Inbound mail: example.com' });
    fireEvent.click(screen.getByRole('button', { name: 'Add route' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Matches'), { target: { value: 'catch_all' } });
    fireEvent.change(within(dialog).getByLabelText('Then'), { target: { value: 'forward' } });
    fireEvent.input(within(dialog).getByLabelText('Forward to'), { target: { value: 'x@example.com' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add route' }));
    expect(await within(dialog).findAllByText('A forward there would loop.')).not.toHaveLength(0);
  });

  it('disables, edits and deletes a route', async () => {
    const m = mockFetch(base({
      'PATCH /api/v1/domains/d1/inbound/routes/r1': (c: RecordedCall) => json({ ...route(), ...(c.body as object) }),
      'DELETE /api/v1/domains/d1/inbound/routes/r1': undefined,
    }));
    renderWithApp(<DomainInbound id="d1" />, on);
    await screen.findByRole('heading', { name: 'Inbound mail: example.com' });
    fireEvent.click(await screen.findByRole('button', { name: 'Disable route Support' }));
    await waitFor(() => expect(m.callsTo('PATCH', '/api/v1/domains/d1/inbound/routes/r1')).toHaveLength(1));
    expect(m.callsTo('PATCH', '/api/v1/domains/d1/inbound/routes/r1')[0].body).toEqual({ enabled: false });

    fireEvent.click(screen.getByRole('button', { name: 'Edit route Support' }));
    const dialog = screen.getByRole('dialog');
    expect((within(dialog).getByLabelText('Address (before the @)') as HTMLInputElement).value).toBe('support');
    fireEvent.input(within(dialog).getByLabelText('Order'), { target: { value: '5' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save route' }));
    await waitFor(() => expect(m.callsTo('PATCH', '/api/v1/domains/d1/inbound/routes/r1')).toHaveLength(2));
    expect(m.callsTo('PATCH', '/api/v1/domains/d1/inbound/routes/r1')[1].body).toMatchObject({ order: 5, match: { kind: 'address', localPart: 'support' }, action: { kind: 'store' } });

    fireEvent.click(await screen.findByRole('button', { name: 'Delete route Support' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete route' }));
    await waitFor(() => expect(m.callsTo('DELETE', '/api/v1/domains/d1/inbound/routes/r1')).toHaveLength(1));
  });

  it('tests an address against the routes', async () => {
    const m = mockFetch(base({
      'GET /api/v1/domains/d1/inbound/routes/match': (c: RecordedCall) => ({ address: c.query.get('address'), domainEnabled: true, route: route(), reply: '250' }),
    }));
    renderWithApp(<DomainInbound id="d1" />, on);
    await screen.findByRole('heading', { name: 'Inbound mail: example.com' });
    fireEvent.input(screen.getByLabelText('Address'), { target: { value: 'support+x' } });
    fireEvent.click(screen.getByRole('button', { name: 'Test' }));
    const result = await screen.findByTestId('probe-result');
    expect(result.textContent).toContain('accepted');
    expect(result.textContent).toContain('Support');
    expect(m.callsTo('GET', '/api/v1/domains/d1/inbound/routes/match')[0].query.get('address')).toBe('support+x@example.com');
  });
});

// The settings test renders the page the same way; this keeps the intent of the first call readable.
function InboundMessageDetailPlaceholder() {
  return <DomainInbound id="d1" />;
}
