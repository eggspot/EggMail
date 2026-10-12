import { Fragment } from 'preact';
import type { DnsRecord, DomainStatus, RecordStatus } from '../api/types';
import { Chip, CopyButton, Notice } from './ui';
import type { Tone } from './ui';

const RECORD_LABEL: Record<RecordStatus, string> = { ok: 'OK', missing: 'Missing', invalid: 'Invalid', pending: 'Pending' };
const RECORD_TONE: Record<RecordStatus, Tone> = { ok: 'ok', missing: 'bad', invalid: 'bad', pending: 'info' };
const PURPOSE_LABEL: Record<string, string> = { dkim: 'DKIM', return_path: 'Return-path', spf: 'SPF', dmarc: 'DMARC' };

export function RecordStatusChip({ status }: { status: RecordStatus }) {
  return <Chip tone={RECORD_TONE[status] ?? 'neutral'}>{RECORD_LABEL[status] ?? status}</Chip>;
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
            const broken = r.status === 'invalid' || r.status === 'missing';
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
                      <CopyButton text={r.host} what={`${PURPOSE_LABEL[r.purpose] ?? r.purpose} host`} />
                    </div>
                  </td>
                  <td>
                    <div class="value-cell">
                      <code class="dns-value" data-testid="dns-value">
                        {r.value}
                      </code>
                      <CopyButton text={r.value} what={`${PURPOSE_LABEL[r.purpose] ?? r.purpose} value`} />
                    </div>
                  </td>
                  <td class="num">{r.ttl}</td>
                  <td>{PURPOSE_LABEL[r.purpose] ?? r.purpose}</td>
                  <td>
                    <RecordStatusChip status={r.status} />
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
          The return-path record is a CNAME to the bounce domain; it makes bounces reach EggMail. If it is missing, the shared bounce domain is used.
        </li>
        <li>SPF is informational: keep a single SPF record per domain and merge the include into it if you already have one.</li>
        <li>DMARC is informational and never blocks sending.</li>
      </ul>
    </Notice>
  );
}
