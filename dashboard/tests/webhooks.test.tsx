import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Webhooks from '../src/pages/Webhooks';
import type { Webhook, WebhookAttempt } from '../src/api/types';
import { json, mockFetch, problem, renderWithApp } from './helpers';
import type { RecordedCall } from './helpers';

const hook: Webhook = { id: 'w1', url: 'https://hooks.example/a', event_types: ['message.delivered'], enabled: true };
const off: Webhook = { id: 'w2', url: 'https://old.example/b', event_types: ['message.bounced'], enabled: false, disabledReason: 'Endpoint answered 410 Gone; disabled automatically.' };
const attempts: WebhookAttempt[] = [
  { id: 'a1', outboxId: 'o1', eventType: 'message.delivered', at: '2026-10-12T08:00:00.000Z', status: 200, durationMs: 142, errorClass: null, snippet: 'ok-body' },
  { id: 'a2', outboxId: 'o2', eventType: 'message.bounced', at: '2026-10-12T07:00:00.000Z', status: 500, durationMs: 1500, errorClass: 'http_5xx', snippet: '<b>boom</b>' },
  { id: 'a3', outboxId: 'o3', eventType: 'message.bounced', at: '2026-10-12T06:00:00.000Z', status: null, durationMs: 15000, errorClass: 'timeout', snippet: null },
];

describe('Webhooks page', () => {
  it('lists endpoints with enabled/disabled state, event types and the disabled reason', async () => {
    mockFetch({ 'GET /api/v1/webhooks': [hook, off] });
    renderWithApp(<Webhooks />);
    expect(await screen.findByRole('heading', { name: 'https://hooks.example/a' })).toBeTruthy();
    expect(screen.getByText('Enabled')).toBeTruthy();
    expect(screen.getByText('Disabled')).toBeTruthy();
    expect(screen.getByText(/answered 410 Gone/)).toBeTruthy();
  });

  it('shows an empty state', async () => {
    mockFetch({ 'GET /api/v1/webhooks': [] });
    renderWithApp(<Webhooks />);
    expect(await screen.findByText('No webhook endpoints')).toBeTruthy();
  });

  it('requires a URL and at least one event type', async () => {
    const m = mockFetch({ 'GET /api/v1/webhooks': [] });
    renderWithApp(<Webhooks />);
    await screen.findByText('No webhook endpoints');
    fireEvent.click(screen.getByRole('button', { name: 'Create endpoint' }));
    expect(await screen.findByText('Enter the endpoint URL.')).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/webhooks')).toHaveLength(0);
    for (const t of ['message.delivered', 'message.bounced']) fireEvent.click(screen.getByLabelText(t));
    fireEvent.input(screen.getByLabelText('Endpoint URL'), { target: { value: 'https://x.example/h' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create endpoint' }));
    expect(await screen.findByText('Select at least one event type.')).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/webhooks')).toHaveLength(0);
  });

  it('shows the signing secret once and removes it after dismissal; never stores it in web storage', async () => {
    const m = mockFetch({
      'GET /api/v1/webhooks': [],
      'POST /api/v1/webhooks': (c: RecordedCall) => json({ id: 'w9', ...(c.body as object), enabled: true, secret: 'whsec_ONLYONCE123' }, 201),
    });
    renderWithApp(<Webhooks />);
    await screen.findByText('No webhook endpoints');
    fireEvent.input(screen.getByLabelText('Endpoint URL'), { target: { value: 'https://x.example/h' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create endpoint' }));
    const secret = await screen.findByTestId('secret-value');
    expect(secret.textContent).toBe('whsec_ONLYONCE123');
    expect(screen.getByText(/shown only once/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Copy secret' })).toBeTruthy();
    expect(JSON.stringify({ ...localStorage })).not.toContain('whsec_');
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('whsec_');
    expect(m.callsTo('POST', '/api/v1/webhooks')[0].body).toEqual({ url: 'https://x.example/h', event_types: ['message.delivered', 'message.bounced'] });
    fireEvent.click(screen.getByRole('button', { name: 'I have saved it' }));
    expect(screen.queryByTestId('secret-value')).toBeNull();
    expect(document.body.textContent).not.toContain('whsec_ONLYONCE123');
  });

  it('shows server-side SSRF/HTTPS validation errors inline on the URL field', async () => {
    mockFetch({
      'GET /api/v1/webhooks': [],
      'POST /api/v1/webhooks': () => problem(400, 'validation_failed', { errors: [{ field: 'url', message: 'Internal addresses are blocked (SSRF protection).' }] }),
    });
    renderWithApp(<Webhooks />);
    await screen.findByText('No webhook endpoints');
    fireEvent.input(screen.getByLabelText('Endpoint URL'), { target: { value: 'https://127.0.0.1/h' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create endpoint' }));
    expect(await screen.findByText('Internal addresses are blocked (SSRF protection).')).toBeTruthy();
    expect(screen.getByLabelText('Endpoint URL').getAttribute('aria-invalid')).toBe('true');
  });

  it('rotates the secret after confirmation and shows the new one once', async () => {
    const m = mockFetch({ 'GET /api/v1/webhooks': [hook], 'POST /api/v1/webhooks/:id/rotate-secret': { ...hook, secret: 'whsec_NEW' } });
    renderWithApp(<Webhooks />);
    fireEvent.click(await screen.findByRole('button', { name: 'Rotate secret' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/both the old and the new secret/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Rotate secret' }));
    expect((await screen.findByTestId('secret-value')).textContent).toBe('whsec_NEW');
    expect(m.callsTo('POST', '/api/v1/webhooks/w1/rotate-secret')).toHaveLength(1);
  });

  it('enables/disables with PATCH and deletes after confirmation', async () => {
    const m = mockFetch({ 'GET /api/v1/webhooks': [hook], 'PATCH /api/v1/webhooks/:id': { ...hook, enabled: false }, 'DELETE /api/v1/webhooks/:id': () => undefined });
    renderWithApp(<Webhooks />);
    fireEvent.click(await screen.findByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(m.callsTo('PATCH', '/api/v1/webhooks/w1')).toHaveLength(1));
    expect(m.callsTo('PATCH', '/api/v1/webhooks/w1')[0].body).toEqual({ enabled: false });
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete endpoint' }));
    await waitFor(() => expect(m.callsTo('DELETE', '/api/v1/webhooks/w1')).toHaveLength(1));
  });

  it('edits url and event types with PATCH', async () => {
    const m = mockFetch({ 'GET /api/v1/webhooks': [hook], 'PATCH /api/v1/webhooks/:id': hook });
    renderWithApp(<Webhooks />);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const inputs = screen.getAllByLabelText('Endpoint URL');
    fireEvent.input(inputs[inputs.length - 1], { target: { value: 'https://hooks.example/new' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(m.callsTo('PATCH', '/api/v1/webhooks/w1')).toHaveLength(1));
    expect(m.callsTo('PATCH', '/api/v1/webhooks/w1')[0].body).toEqual({ url: 'https://hooks.example/new', event_types: ['message.delivered'] });
  });
});

describe('Webhooks attempts log', () => {
  it('shows status chips, durations, error class and the response snippet as plain text', async () => {
    mockFetch({ 'GET /api/v1/webhooks': [hook], 'GET /api/v1/webhooks/:id/attempts': attempts });
    renderWithApp(<Webhooks />);
    fireEvent.click(await screen.findByRole('button', { name: 'Show attempts' }));
    const table = await screen.findByRole('table', { name: /Delivery attempts/ });
    expect(within(table).getByText('200')).toBeTruthy();
    expect(within(table).getByText('500')).toBeTruthy();
    expect(within(table).getByText('No response')).toBeTruthy();
    expect(within(table).getByText('142 ms')).toBeTruthy();
    expect(within(table).getByText('15.0 s')).toBeTruthy();
    expect(within(table).getByText('timeout')).toBeTruthy();
    // snippet rendered as text, never as markup
    expect(within(table).getByText('<b>boom</b>')).toBeTruthy();
    expect(table.querySelector('b')).toBeNull();
  });

  it('send test event posts to /test and reloads the attempts', async () => {
    const m = mockFetch({
      'GET /api/v1/webhooks': [hook],
      'POST /api/v1/webhooks/:id/test': { outboxId: 'o9' },
      'GET /api/v1/webhooks/:id/attempts': attempts,
    });
    renderWithApp(<Webhooks />);
    fireEvent.click(await screen.findByRole('button', { name: 'Send test event' }));
    expect(await screen.findByText(/Test event sent/)).toBeTruthy();
    await screen.findByRole('table', { name: /Delivery attempts/ });
    expect(m.callsTo('POST', '/api/v1/webhooks/w1/test')).toHaveLength(1);
    expect(m.callsTo('GET', '/api/v1/webhooks/w1/attempts').length).toBeGreaterThan(0);
  });

  it('replays an attempt after confirmation and reports the outcome', async () => {
    const m = mockFetch({ 'GET /api/v1/webhooks': [hook], 'GET /api/v1/webhooks/:id/attempts': attempts, 'POST /api/v1/webhook-events/:outboxId/replay': () => json({ status: 'queued' }, 202) });
    renderWithApp(<Webhooks />);
    fireEvent.click(await screen.findByRole('button', { name: 'Show attempts' }));
    const btn = await screen.findAllByRole('button', { name: /^Replay message\.bounced/ });
    fireEvent.click(btn[0]);
    const dialog = await screen.findByRole('dialog');
    expect(m.callsTo('POST', '/api/v1/webhook-events/o2/replay')).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Replay delivery' }));
    await waitFor(() => expect(m.callsTo('POST', '/api/v1/webhook-events/o2/replay')).toHaveLength(1));
    expect(await screen.findByText(/Delivery re-queued/)).toBeTruthy();
  });

  it('shows an error when replay fails', async () => {
    mockFetch({ 'GET /api/v1/webhooks': [hook], 'GET /api/v1/webhooks/:id/attempts': attempts, 'POST /api/v1/webhook-events/:outboxId/replay': () => problem(404, 'not_found') });
    renderWithApp(<Webhooks />);
    fireEvent.click(await screen.findByRole('button', { name: 'Show attempts' }));
    fireEvent.click((await screen.findAllByRole('button', { name: /^Replay/ }))[0]);
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Replay delivery' }));
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toBeTruthy();
  });
});
