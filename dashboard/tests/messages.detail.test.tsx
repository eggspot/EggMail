import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import MessageDetail from '../src/pages/MessageDetail';
import { flush, mockFetch, problem, renderWithApp } from './helpers';
import { MSG_ID, detail, event } from './messageFixtures';

const base = (over: Record<string, unknown> = {}) => ({
  [`GET /api/v1/messages/${MSG_ID}`]: detail(),
  [`GET /api/v1/messages/${MSG_ID}/events`]: [event({ id: 'e0', type: 'queued', at: '2026-10-11T09:30:00.000Z', smtpCode: null, enhancedCode: null, mxHost: null, route: null, message: 'Accepted for delivery' }), event()],
  ...over,
});

describe('Message detail', () => {
  it('shows metadata, the event timeline (oldest first) and the text view by default', async () => {
    mockFetch(base());
    renderWithApp(<MessageDetail id={MSG_ID} />);
    expect(await screen.findByRole('heading', { level: 1, name: 'Welcome to Acme' })).toBeTruthy();
    expect(screen.getByText('Acme <noreply@example.com>')).toBeTruthy();
    expect(screen.getByText('alex@gmail.com', { selector: 'dd' })).toBeTruthy();
    const items = await screen.findAllByRole('listitem');
    const timeline = items.filter((li) => li.hasAttribute('data-event-type'));
    expect(timeline.map((li) => li.getAttribute('data-event-type'))).toEqual(['queued', 'delivered']);
    expect(screen.getByText('250 2.0.0')).toBeTruthy();
    expect(screen.getByText('MX gmail-smtp-in.l.google.com')).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'Text', selected: true })).toBeTruthy();
    expect(screen.getByTestId('text-view').textContent).toBe('Hello Alex, plain text body.');
    expect(document.querySelector('iframe')).toBeNull();
  });

  it('shows TLS details in an expandable section', async () => {
    mockFetch(
      base({
        [`GET /api/v1/messages/${MSG_ID}/events`]: [
          event({ tls: { used: true, version: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', verified: false, policy: 'opportunistic', peerSubject: 'CN=mx.example.net', peerIssuer: 'CN=Issuer', peerSha256: 'ab12' } }),
        ],
      }),
    );
    renderWithApp(<MessageDetail id={MSG_ID} />);
    const summary = await screen.findByText(/TLS: TLS 1\.3 \(certificate not verified\)/);
    const details = summary.closest('details') as HTMLDetailsElement;
    expect(details.open).toBe(false);
    expect(within(details).getByText('TLS_AES_256_GCM_SHA384')).toBeTruthy();
    expect(within(details).getByText('opportunistic')).toBeTruthy();
    expect(within(details).getByText('CN=mx.example.net')).toBeTruthy();
  });

  it('highlights possible_duplicate and explains aborted_by_switch', async () => {
    mockFetch(
      base({
        [`GET /api/v1/messages/${MSG_ID}/events`]: [
          event({ id: 'a', type: 'aborted_by_switch', smtpCode: null, enhancedCode: null }),
          event({ id: 'p', type: 'possible_duplicate', smtpCode: null, enhancedCode: null }),
        ],
      }),
    );
    renderWithApp(<MessageDetail id={MSG_ID} />);
    const note = await screen.findByRole('note');
    expect(note.textContent).toContain('may have been sent twice');
    expect(note.textContent).toContain('storage switch');
    expect(screen.getByText(/aborted because a storage switch quiesced/)).toBeTruthy();
    expect(document.querySelector('li.timeline-flagged')?.getAttribute('data-event-type')).toBe('possible_duplicate');
  });

  it('switches tabs with the keyboard and renders HTML only in a sandboxed iframe', async () => {
    mockFetch(base({ [`GET /api/v1/messages/${MSG_ID}`]: detail({ content: { state: 'available', text: 'T', html: '<h1 id="victim">Injected heading</h1><script>window.pwned=1</script>', attachments: [] } }) }));
    renderWithApp(<MessageDetail id={MSG_ID} />);
    const textTab = await screen.findByRole('tab', { name: 'Text' });
    fireEvent.keyDown(textTab, { key: 'ArrowRight' });
    const htmlTab = await screen.findByRole('tab', { name: 'HTML (sandboxed)', selected: true });
    expect(htmlTab).toBeTruthy();
    const frame = document.querySelector('iframe') as HTMLIFrameElement;
    expect(frame).toBeTruthy();
    expect(frame.hasAttribute('sandbox')).toBe(true);
    expect(frame.getAttribute('sandbox')).toBe('');
    expect(frame.getAttribute('referrerpolicy')).toBe('no-referrer');
    expect(frame.getAttribute('title')).toBeTruthy();
    const srcdoc = frame.getAttribute('srcdoc') ?? '';
    expect(srcdoc.indexOf('Content-Security-Policy')).toBeGreaterThan(-1);
    expect(srcdoc.indexOf('Content-Security-Policy')).toBeLessThan(srcdoc.indexOf('Injected heading'));
    expect(srcdoc).toContain("default-src 'none'");
    // The message HTML must not exist in the app DOM.
    expect(document.getElementById('victim')).toBeNull();
    expect(document.body.querySelector('script')).toBeNull();
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
    fireEvent.keyDown(htmlTab, { key: 'ArrowRight' });
    expect(await screen.findByRole('tab', { name: /Attachments/, selected: true })).toBeTruthy();
    expect(screen.getByText('This message has no attachments.')).toBeTruthy();
    fireEvent.keyDown(screen.getByRole('tab', { name: /Attachments/ }), { key: 'Home' });
    expect(await screen.findByRole('tab', { name: 'Text', selected: true })).toBeTruthy();
  });

  it('lists attachments and explains when their content was not stored', async () => {
    mockFetch(
      base({
        [`GET /api/v1/messages/${MSG_ID}`]: detail({ content: { state: 'available', text: 'T', attachments: [{ filename: 'contract.pdf', content_type: 'application/pdf', size: 1_200_000 }] } }),
      }),
    );
    renderWithApp(<MessageDetail id={MSG_ID} />);
    fireEvent.click(await screen.findByRole('tab', { name: /Attachments \(1\)/ }));
    expect(screen.getByText('contract.pdf')).toBeTruthy();
    expect(screen.getByText('application/pdf')).toBeTruthy();
    expect(screen.getByText(/were not stored/)).toBeTruthy();
  });

  it('shows the body_expired explanation instead of tabs, keeps the events, and disables resend', async () => {
    mockFetch(base({ [`GET /api/v1/messages/${MSG_ID}`]: detail({ content: { state: 'body_expired', attachments: [] } }) }));
    renderWithApp(<MessageDetail id={MSG_ID} />);
    expect(await screen.findByText('The message content has expired')).toBeTruthy();
    expect(screen.queryByRole('tablist')).toBeNull();
    expect((await screen.findAllByRole('listitem')).some((li) => li.getAttribute('data-event-type') === 'delivered')).toBe(true);
    expect((screen.getByRole('button', { name: 'Resend' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('falls back to /content when the detail has no body, and handles 410 body_expired from it', async () => {
    const noBody = detail({ content: { state: 'available', attachments: [] } });
    const m = mockFetch(base({ [`GET /api/v1/messages/${MSG_ID}`]: noBody, [`GET /api/v1/messages/${MSG_ID}/content`]: { text: 'Fetched text', html: '<p>x</p>' } }));
    renderWithApp(<MessageDetail id={MSG_ID} />);
    await waitFor(() => expect(screen.getByTestId('text-view').textContent).toBe('Fetched text'));
    expect(m.callsTo('GET', `/api/v1/messages/${MSG_ID}/content`)).toHaveLength(1);
  });

  it('handles 410 body_expired from /content gracefully', async () => {
    mockFetch(
      base({
        [`GET /api/v1/messages/${MSG_ID}`]: detail({ content: { state: 'available', attachments: [] } }),
        [`GET /api/v1/messages/${MSG_ID}/content`]: problem(410, 'body_expired', { expired_at: '2026-10-10T00:00:00Z', retention_days: 7 }),
      }),
    );
    renderWithApp(<MessageDetail id={MSG_ID} />);
    expect(await screen.findByText('The message content has expired')).toBeTruthy();
  });

  it('shows a not-found state for unknown messages', async () => {
    mockFetch({ [`GET /api/v1/messages/${MSG_ID}`]: problem(404, 'message_not_found'), [`GET /api/v1/messages/${MSG_ID}/events`]: problem(404, 'message_not_found') });
    renderWithApp(<MessageDetail id={MSG_ID} />);
    expect(await screen.findByText('Message not found')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Back to messages' }).getAttribute('href')).toBe('/messages');
  });

  it('explains statsonly mode without calling the message API', async () => {
    const m = mockFetch({});
    renderWithApp(<MessageDetail id={MSG_ID} />, { mode: 'statsonly' });
    await flush();
    expect(screen.getByText('Per-message history is not recorded')).toBeTruthy();
    expect(m.calls).toHaveLength(0);
  });

  it('shows an error notice when the events cannot be loaded but still shows the message', async () => {
    mockFetch(base({ [`GET /api/v1/messages/${MSG_ID}/events`]: problem(500, 'server_error') }));
    renderWithApp(<MessageDetail id={MSG_ID} />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByRole('heading', { level: 1, name: 'Welcome to Acme' })).toBeTruthy();
  });
});

describe('Resend', () => {
  const open = async () => {
    renderWithApp(<MessageDetail id={MSG_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Resend' }));
    return screen.findByRole('dialog');
  };

  it('asks for confirmation and then shows the new message id', async () => {
    const m = mockFetch(base({ [`POST /api/v1/messages/${MSG_ID}/resend`]: new Response(JSON.stringify({ id: 'f'.repeat(32), recomposed: true }), { status: 202, headers: { 'Content-Type': 'application/json' } }) }));
    const dialog = await open();
    expect(m.callsTo('POST', `/api/v1/messages/${MSG_ID}/resend`)).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Resend message' }));
    const link = await screen.findByRole('link', { name: 'f'.repeat(32) });
    expect(link.getAttribute('href')).toBe(`/messages/${'f'.repeat(32)}`);
    expect(screen.getByText(/re-composed from the stored content/)).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('can be cancelled without calling the API', async () => {
    const m = mockFetch(base());
    const dialog = await open();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(m.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
  });

  it.each([
    [409, 'attachments_not_stored', /attachments that were not stored/],
    [410, 'body_expired', /content has expired/],
    [410, 'history_not_recorded', /not recorded/],
    [404, 'message_not_found', /message was not found/],
  ])('maps %i %s to a friendly message inside the dialog', async (status, code, text) => {
    mockFetch(base({ [`POST /api/v1/messages/${MSG_ID}/resend`]: problem(status, code) }));
    const dialog = await open();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Resend message' }));
    const alert = await within(dialog).findByRole('alert');
    expect(alert.textContent).toMatch(text);
  });

  it('shows the Retry-After seconds for 429', async () => {
    mockFetch(base({ [`POST /api/v1/messages/${MSG_ID}/resend`]: problem(429, 'rate_limited', {}, { 'Retry-After': '12' }) }));
    const dialog = await open();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Resend message' }));
    expect((await within(dialog).findByRole('alert')).textContent).toContain('Retry in 12 s');
  });
});
