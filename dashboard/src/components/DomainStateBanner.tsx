import type { Domain } from '../api/types';
import { formatDateTime } from '../lib/format';
import { Notice } from './ui';

/** Banner(s) explaining what the domain state means for sending (design section 8). */
export function DomainStateBanner({ domain }: { domain: Domain }) {
  const banners = [];
  if (domain.status === 'failed') {
    banners.push(
      <Notice key="failed" tone="bad" title="Verification failed">
        <p>
          The DNS records for {domain.name} could not be verified. Sending from this domain is paused. Fix the records marked missing, invalid or mismatch below, then choose Check DNS.
        </p>
        {domain.lastError && <p class="small">{domain.lastError}</p>}
      </Notice>,
    );
  } else if (domain.status === 'temporary_failure') {
    banners.push(
      <Notice key="tf" tone="warn" title="Temporary verification failure">
        <p>
          Some records were missing or changed at the last check{domain.lastCheckedAt ? ` (${formatDateTime(domain.lastCheckedAt)})` : ''}. Sending continues for now, but it
          will be paused if the records stay broken beyond the grace period. Fix the records marked missing, invalid or mismatch below.
        </p>
        {domain.lastError && <p class="small">{domain.lastError}</p>}
      </Notice>,
    );
  } else if (domain.status === 'pending' || domain.status === 'verifying') {
    banners.push(
      <Notice key="pending" tone="info" title={domain.status === 'pending' ? 'Waiting for DNS records' : 'Verifying'}>
        <p>Sending from this domain is blocked until it is verified. Publish the records below, then choose Check DNS. DNS changes can take a while to spread.</p>
      </Notice>,
    );
  }
  if (domain.sendingPaused && domain.status !== 'failed') {
    banners.push(
      <Notice key="paused" tone="bad" title="Sending is paused">
        <p>Sending from {domain.name} is currently paused.</p>
      </Notice>,
    );
  }
  if (!banners.length) return null;
  return <>{banners}</>;
}
