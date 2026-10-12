import type { DeliveryEvent, MessageDetail, MessageSummary, StatsRow } from '../src/api/types';

export const MSG_ID = '0199a00000007000800000000000abcd';

export function summary(over: Partial<MessageSummary> = {}): MessageSummary {
  return {
    id: MSG_ID,
    receivedAt: '2026-10-11T09:30:00.000Z',
    subject: 'Welcome to Acme',
    from: 'Acme <noreply@example.com>',
    recipients: ['alex@gmail.com'],
    status: 'delivered',
    size: 2048,
    ...over,
  };
}

export function detail(over: Partial<MessageDetail> = {}): MessageDetail {
  return {
    ...summary(),
    tenantId: 't_1',
    content: { state: 'available', text: 'Hello Alex, plain text body.', html: '<h1>Hello Alex</h1><p>HTML body</p>', attachments: [] },
    rawRetained: false,
    ...over,
  };
}

export function event(over: Partial<DeliveryEvent> = {}): DeliveryEvent {
  return {
    id: 'e1',
    type: 'delivered',
    at: '2026-10-11T09:30:05.000Z',
    recipient: 'alex@gmail.com',
    smtpCode: 250,
    enhancedCode: '2.0.0',
    message: '2.0.0 OK',
    mxHost: 'gmail-smtp-in.l.google.com',
    route: 'direct',
    tls: null,
    ...over,
  };
}

export function statsRow(over: Partial<StatsRow> = {}): StatsRow {
  return {
    period: '2026-10-11T09:00:00.000Z',
    sendingDomain: 'example.com',
    recipientDomain: 'gmail.com',
    accepted: 100,
    delivered: 90,
    deferred: 5,
    hardBounce: 2,
    softBounce: 1,
    expired: 0,
    complained: 1,
    rejected: 0,
    suppressed: 1,
    ...over,
  };
}
