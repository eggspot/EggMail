import type { DeliveryEvent, TlsDetails } from '../api/types';
import { formatDateTime } from '../lib/format';
import { Chip, StatusChip } from './ui';

function TlsBlock({ tls }: { tls: TlsDetails }) {
  const rows: [string, string][] = [];
  if (tls.used !== undefined) rows.push(['TLS used', tls.used ? 'yes' : 'no (plaintext)']);
  if (tls.version) rows.push(['Version', tls.version]);
  if (tls.cipher) rows.push(['Cipher', tls.cipher]);
  if (tls.verified !== undefined) rows.push(['Certificate verified', tls.verified ? 'yes' : 'no']);
  if (tls.policy) rows.push(['Policy applied', tls.policy]);
  if (tls.peerSubject) rows.push(['Peer subject', tls.peerSubject]);
  if (tls.peerIssuer) rows.push(['Peer issuer', tls.peerIssuer]);
  if (tls.peerSha256) rows.push(['Peer SHA-256', tls.peerSha256]);
  return (
    <details class="tls-details">
      <summary>
        TLS: {tls.used === false ? 'not used' : (tls.version ?? 'used')}
        {tls.verified === false && ' (certificate not verified)'}
      </summary>
      <dl class="kv">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd class={k === 'Peer SHA-256' ? 'mono' : undefined}>{v}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

const EXPLANATIONS: Record<string, string> = {
  possible_duplicate:
    'This delivery may have been sent twice. It was in flight when the storage switch quiesced, after the end of the message data was sent, so the remote server may already have accepted it. Delivery is at-least-once.',
  aborted_by_switch: 'The delivery attempt was aborted because a storage switch quiesced the server. The delivery was requeued with its retry state preserved.',
  complained: 'The recipient reported this message as spam through a feedback loop.',
  expired: 'The message stayed in the queue past its maximum lifetime and was given up.',
  suppressed: 'The recipient is on the suppression list, so no delivery was attempted.',
};

function EventItem({ e }: { e: DeliveryEvent }) {
  const flagged = e.type === 'possible_duplicate';
  const code = [e.smtpCode, e.enhancedCode].filter((x) => x !== null && x !== undefined && x !== '').join(' ');
  return (
    <li data-event-type={e.type} class={flagged ? 'timeline-flagged' : undefined}>
      <div class="row">
        <StatusChip status={e.type} />
        <time dateTime={e.at} class="muted small">
          {formatDateTime(e.at)}
        </time>
        {e.recipient && <span class="small">to {e.recipient}</span>}
        {code && <code>{code}</code>}
        {e.route && <Chip tone="neutral">route: {e.route}</Chip>}
      </div>
      {e.mxHost && <div class="small muted">MX {e.mxHost}</div>}
      {e.message && <div class="small">{e.message}</div>}
      {EXPLANATIONS[e.type] && (
        <p class={`small ${flagged ? 'notice notice-warn' : 'muted'}`} role={flagged ? 'note' : undefined}>
          {EXPLANATIONS[e.type]}
        </p>
      )}
      {e.tls && <TlsBlock tls={e.tls} />}
    </li>
  );
}

/** Oldest-first list of delivery events with TLS details and explanations for the unusual types. */
export function EventTimeline({ events }: { events: DeliveryEvent[] }) {
  if (!events.length) return <p class="muted">No delivery events recorded yet.</p>;
  const sorted = [...events].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  return (
    <ol class="timeline" aria-label="Delivery events">
      {sorted.map((e) => (
        <EventItem key={e.id} e={e} />
      ))}
    </ol>
  );
}
