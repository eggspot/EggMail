import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import MessageDetail from '../src/pages/MessageDetail';
import { flush, mockFetch, problem, renderWithApp } from './helpers';
import { MSG_ID, detail, event } from './messageFixtures';

const CANCEL = `POST /api/v1/messages/${MSG_ID}/cancel`;
const noCode = { smtpCode: null, enhancedCode: null, mxHost: null, route: null };

const base = (over: Record<string, unknown> = {}) => ({
  [`GET /api/v1/messages/${MSG_ID}`]: detail({ status: 'deferred', recipients: ['a@gmail.com', 'b@gmail.com'] }),
  [`GET /api/v1/messages/${MSG_ID}/events`]: [
    event({ id: 'q1', type: 'queued', recipient: 'a@gmail.com', ...noCode }),
    event({ id: 'q2', type: 'queued', recipient: 'b@gmail.com', ...noCode }),
    event({ id: 'd1', type: 'deferred', recipient: 'a@gmail.com', smtpCode: 451, enhancedCode: '4.7.1' }),
  ],
  ...over,
});

const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

describe('Cancel delivery', () => {
  it('is offered only while a recipient is still waiting', async () => {
    mockFetch({
      [`GET /api/v1/messages/${MSG_ID}`]: detail({ status: 'delivered' }),
      [`GET /api/v1/messages/${MSG_ID}/events`]: [event({ type: 'delivered' })],
    });
    const first = renderWithApp(<MessageDetail id={MSG_ID} />);
    await screen.findByRole('heading', { level: 1, name: 'Welcome to Acme' });
    await flush();
    expect(screen.queryByRole('button', { name: 'Cancel delivery' })).toBeNull();
    first.unmount();

    // Deferred, but the timeline shows every recipient finished: nothing is left to cancel.
    mockFetch({
      [`GET /api/v1/messages/${MSG_ID}`]: detail({ status: 'deferred' }),
      [`GET /api/v1/messages/${MSG_ID}/events`]: [event({ type: 'delivered' })],
    });
    renderWithApp(<MessageDetail id={MSG_ID} />);
    await screen.findByRole('heading', { level: 1, name: 'Welcome to Acme' });
    await flush();
    expect(screen.queryByRole('button', { name: 'Cancel delivery' })).toBeNull();
  });

  it('asks which recipients, sends exactly those and reloads the message', async () => {
    const m = mockFetch(base({ [CANCEL]: ok({ id: MSG_ID, status: 'deferred', cancelled: ['b@gmail.com'], inFlight: [], notPending: [] }) }));
    renderWithApp(<MessageDetail id={MSG_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel delivery' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getAllByRole('checkbox')).toHaveLength(2);
    expect(m.callsTo('POST', `/api/v1/messages/${MSG_ID}/cancel`)).toHaveLength(0);

    fireEvent.click(within(dialog).getByRole('checkbox', { name: 'a@gmail.com' })); // keep a@
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel delivery to 1 recipient' }));

    const result = await screen.findByTestId('cancel-result');
    expect(result.textContent).toContain('Delivery cancelled for 1 recipient');
    expect(result.textContent).toContain('b@gmail.com');
    expect(m.callsTo('POST', `/api/v1/messages/${MSG_ID}/cancel`)[0].body).toEqual({ recipients: ['b@gmail.com'] });
    await waitFor(() => expect(m.callsTo('GET', `/api/v1/messages/${MSG_ID}`).length).toBeGreaterThan(1));
    expect(m.callsTo('GET', `/api/v1/messages/${MSG_ID}/events`).length).toBeGreaterThan(1);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('names the single waiting recipient instead of a list', async () => {
    mockFetch(
      base({
        [`GET /api/v1/messages/${MSG_ID}`]: detail({ status: 'queued', recipients: ['a@gmail.com'] }),
        [`GET /api/v1/messages/${MSG_ID}/events`]: [event({ id: 'q1', type: 'queued', recipient: 'a@gmail.com', ...noCode })],
      }),
    );
    renderWithApp(<MessageDetail id={MSG_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel delivery' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByRole('checkbox')).toBeNull();
    expect(within(dialog).getByText('a@gmail.com')).toBeTruthy();
  });

  it('refuses to send an empty selection', async () => {
    const m = mockFetch(base());
    renderWithApp(<MessageDetail id={MSG_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel delivery' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('checkbox', { name: 'a@gmail.com' }));
    fireEvent.click(within(dialog).getByRole('checkbox', { name: 'b@gmail.com' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel delivery to 0 recipients' }));
    expect((await within(dialog).findByRole('alert')).textContent).toContain('Select at least one recipient');
    expect(m.callsTo('POST', `/api/v1/messages/${MSG_ID}/cancel`)).toHaveLength(0);
  });

  it('reports the recipients that are being delivered and were left alone', async () => {
    mockFetch(base({ [CANCEL]: ok({ id: MSG_ID, status: 'deferred', cancelled: ['b@gmail.com'], inFlight: ['a@gmail.com'], notPending: [] }) }));
    renderWithApp(<MessageDetail id={MSG_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel delivery' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel delivery to 2 recipients' }));
    const result = await screen.findByTestId('cancel-result');
    expect(result.textContent).toContain('Not cancelled, because a delivery attempt is running right now: a@gmail.com');
  });

  it('shows the server explanation of a conflict inside the dialog', async () => {
    mockFetch(
      base({
        [CANCEL]: problem(409, 'conflict', { detail: 'Every recipient that is still waiting is being delivered right now. Try again when the attempt has ended.', in_flight: ['a@gmail.com'] }),
      }),
    );
    renderWithApp(<MessageDetail id={MSG_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel delivery' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel delivery to 2 recipients' }));
    expect((await within(dialog).findByRole('alert')).textContent).toContain('being delivered right now');
    expect(screen.queryByTestId('cancel-result')).toBeNull();
  });

  it('can be dismissed without calling the API', async () => {
    const m = mockFetch(base());
    renderWithApp(<MessageDetail id={MSG_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel delivery' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(m.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
  });
});
