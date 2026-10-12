import { daysUntil } from '../lib/format';
import { Chip } from './ui';

export const CERT_WARN_DAYS = 14;

/** Days-left chip: warning under 14 days, bad when expired. The text always says what it means. */
export function CertificateExpiry({ notAfter }: { notAfter: string }) {
  const days = daysUntil(notAfter);
  if (days < 0) return <Chip tone="bad">expired {Math.abs(days)} days ago</Chip>;
  if (days < CERT_WARN_DAYS) return <Chip tone="warn">expires in {days} days</Chip>;
  return <Chip tone="ok">{days} days left</Chip>;
}
