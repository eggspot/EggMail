import type { DnsRecord, Domain } from '../src/api/types';

export const LONG_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' + 'x'.repeat(340) + 'IDAQAB';

export function records(over: Partial<Record<DnsRecord['purpose'], Partial<DnsRecord>>> = {}): DnsRecord[] {
  const base: DnsRecord[] = [
    { type: 'TXT', host: 'eggmail1._domainkey.mail.example.com', value: `v=DKIM1; k=rsa; p=${LONG_KEY}`, ttl: 3600, purpose: 'dkim', required: true, status: 'ok', expected: `v=DKIM1; k=rsa; p=${LONG_KEY}`, found: `v=DKIM1; k=rsa; p=${LONG_KEY}` },
    { type: 'CNAME', host: 'bounces.mail.example.com', value: 'bounce.eggmail.example.net', ttl: 3600, purpose: 'return_path', required: true, status: 'ok', expected: 'bounce.eggmail.example.net', found: 'bounce.eggmail.example.net' },
    { type: 'TXT', host: 'mail.example.com', value: 'v=spf1 include:spf.eggmail.example.net ~all', ttl: 3600, purpose: 'spf', required: false, status: 'pending', expected: 'v=spf1 include:spf.eggmail.example.net ~all' },
    { type: 'TXT', host: '_dmarc.mail.example.com', value: 'v=DMARC1; p=none', ttl: 3600, purpose: 'dmarc', required: false, status: 'ok', expected: 'v=DMARC1; p=none', found: 'v=DMARC1; p=none' },
  ];
  return base.map((r) => ({ ...r, ...(over[r.purpose] ?? {}) }));
}

export function makeDomain(over: Partial<Domain> = {}): Domain {
  return {
    id: 'd1',
    name: 'mail.example.com',
    status: 'verified',
    sendingPaused: false,
    lastCheckedAt: '2026-10-12T07:00:00.000Z',
    nextCheckAt: '2026-10-13T07:00:00.000Z',
    lastError: null,
    readyToSend: true,
    records: records(),
    dkim: { selector: 'eggmail1', publicKey: LONG_KEY, active: true, createdAt: '2026-09-01T00:00:00.000Z' },
    ...over,
  };
}
