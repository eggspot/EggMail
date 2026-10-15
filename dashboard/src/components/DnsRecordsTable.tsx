import { Fragment } from 'preact';
import type { DnsRecord, DomainStatus, RecordStatus } from '../api/types';
import { Chip, CopyButton, Notice } from './ui';
import type { Tone } from './ui';

const RECORD_LABEL: Record<RecordStatus, string> = { ok: 'OK', missing: 'Missing', invalid: 'Invalid', mismatch: 'Mismatch', pending: 'Pending' };
const RECORD_TONE: Record<RecordStatus, Tone> = { ok: 'ok', missing: 'bad', invalid: 'bad', mismatch: 'bad', pending: 'info' };
const RECORD_HELP: Record<RecordStatus, string> = {
  ok: 'Found in DNS as expected.',
  missing: 'Nothing of this kind was found at this name.',
  invalid: 'A record exists but it is malformed, or there are several where only one is allowed.',
  mismatch: 'A record exists but it does not have the expected value.',
  pending: 'Not looked up yet.',
};
export const PURPOSE_LABEL: Record<string, string> = {
  dkim: 'DKIM',
  return_path: 'Return-path',
  spf: 'SPF',
  dmarc: 'DMARC',
  bounce_mx: 'Bounce MX',
  tls_rpt: 'TLS-RPT',
  mta_sts: 'MTA-STS',
  mta_sts_host: 'MTA-STS host',
  ptr: 'Reverse DNS',
};

export function RecordStatusChip({ status }: { status: RecordStatus }) {
  return (
    <Chip tone={RECORD_TONE[status] ?? 'neutral'} title={RECORD_HELP[status]}>
      {RECORD_LABEL[status] ?? status}
    </Chip>
  );
}

const DOMAIN_LABEL: Record<DomainStatus, string> = {
  pending: 'Pending',
  verifying: 'Verifying',
  verified: 'Verified',
  temporary_failure: 'Temporary failure',
  failed: 'Failed',
};
const DOMAIN_TONE: Record<DomainStatus, Tone> = { pending: 'info', verifying: 'info', verified: 'ok', temporary_failure: 'warn', failed: 'bad' };

export function DomainStatusChip({ status }: { status: DomainStatus }) {
  return <Chip tone={DOMAIN_TONE[status] ?? 'neutral'}>{DOMAIN_LABEL[status] ?? status}</Chip>;
}

const BROKEN: RecordStatus[] = ['invalid', 'missing', 'mismatch'];

/** Table of the DNS records a domain needs, with copy buttons and found/expected for broken rows. */
export function DnsRecordsTable({ records }: { records: DnsRecord[] }) {
  return (
    <div class="table-wrap">
      <table class="dns-table">
        <caption class="sr-only">DNS records to publish</caption>
        <thead>
          <tr>
            <th scope="col">Type</th>
            <th scope="col">Host</th>
            <th scope="col">Value</th>
            <th scope="col" class="num">
              TTL
            </th>
            <th scope="col">Purpose</th>
            <th scope="col">Status</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r, i) => {
            const broken = BROKEN.includes(r.status);
            const label = PURPOSE_LABEL[r.purpose] ?? r.purpose;
            return (
              <Fragment key={`${r.host}-${r.purpose}-${i}`}>
                <tr>
                  <td>
                    <code>{r.type}</code>
                  </td>
                  <td>
                    <div class="value-cell">
                      <code class="dns-host" data-testid="dns-host">
                        {r.host}
                      </code>
                      <CopyButton text={r.host} what={`${label} host`} />
                    </div>
                  </td>
                  <td>
                    <div class="value-cell">
                      <code class="dns-value" data-testid="dns-value">
                        {r.value}
                      </code>
                      <CopyButton text={r.value} what={`${label} value`} />
                    </div>
                    {r.note && <p class="dns-note small muted">{r.note}</p>}
                  </td>
                  <td class="num">{r.ttl}</td>
                  <td>{label}</td>
                  <td>
                    <RecordStatusChip status={r.status} />
                    <div class="dns-level" data-testid="dns-level">
                      {r.required ? 'Required' : 'Recommended'}
                    </div>
                  </td>
                </tr>
                {broken && (
                  <tr class="dns-detail">
                    <td colSpan={6}>
                      <dl class="kv">
                        <div>
                          <dt>Found in DNS</dt>
                          <dd>{r.found ? <code class="dns-value">{r.found}</code> : <span class="muted">nothing found</span>}</dd>
                        </div>
                        <div>
                          <dt>Expected</dt>
                          <dd>
                            <code class="dns-value">{r.expected ?? r.value}</code>
                          </dd>
                        </div>
                      </dl>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** How far the domain's records are: the required ones decide whether mail can be sent. */
export function recordProgress(records: DnsRecord[]) {
  const required = records.filter((r) => r.required);
  const recommended = records.filter((r) => !r.required);
  return {
    requiredOk: required.filter((r) => r.status === 'ok').length,
    requiredTotal: required.length,
    recommendedOk: recommended.filter((r) => r.status === 'ok').length,
    recommendedTotal: recommended.length,
  };
}

/** The zone-file text with a button that copies all of it. */
export function ZoneFileBlock({ text }: { text: string }) {
  return (
    <div class="stack">
      <div class="value-cell">
        <span class="label">Zone file (all records, ready to paste or import)</span>
        <CopyButton text={text} what="zone file" />
      </div>
      <pre class="zone-file" data-testid="zone-file" tabIndex={0}>
        {text}
      </pre>
    </div>
  );
}

/** Publishing tips: underscores, long TXT values, optional records. */
export function DnsHints() {
  return (
    <Notice tone="info" title="Tips for publishing these records">
      <ul class="dns-hints">
        <li>
          The DKIM host must keep its leading-underscore label exactly: <code>&lt;selector&gt;._domainkey.&lt;domain&gt;</code>. Some DNS panels strip or reject
          underscores, and many append the zone name automatically. If yours does, enter only the part before your domain, then check the published name.
        </li>
        <li>
          The DKIM value is a long TXT value (an RSA-2048 public key is more than 255 characters). Providers split it into several quoted strings; paste the whole value
          as one piece and do not add spaces. The verifier joins the strings back together.
        </li>
        <li>
          The return-path record is a CNAME to the bounce domain; it makes bounces reach EggMail. If it is missing, the shared bounce domain is used. The bounce MX
          belongs to the bounce domain, so it is published once by whoever runs EggMail, not once per domain.
        </li>
        <li>SPF is recommended: keep a single SPF record per domain and merge the mechanism into it if you already have one (two SPF records break SPF).</li>
        <li>DMARC, TLS-RPT and MTA-STS are recommended and never block sending. DMARC starts in monitoring mode (<code>p=none</code>) and sends reports to the address in <code>rua</code>.</li>
        <li>The reverse DNS (PTR) of the sending IP cannot be set in your domain's zone: ask whoever owns the IP address (usually your hosting provider).</li>
      </ul>
    </Notice>
  );
}
