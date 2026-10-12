import type { SettingItem } from '../api/types';
import { Chip, Field } from './ui';

/** Retention knobs where 0 means "keep forever" (design section 5.1). */
export const KEEP_FOREVER_KEYS = [
  'Retention:MetadataDays',
  'Webhooks:OutboxRetentionDays',
  'Webhooks:AttemptLogDays',
  'Stats:HourlyRetentionDays',
  'Stats:DailyRetentionDays',
];

export type DraftValue = string | number | boolean | null;

/** Client-side check; returns a message or undefined. The server validates again. */
export function validateSetting(item: SettingItem, value: DraftValue): string | undefined {
  if (item.type === 'number') {
    const text = String(value ?? '').trim();
    if (!/^\d+$/.test(text)) return 'Enter a whole number, 0 or greater.';
    const n = Number(text);
    if (item.key === 'Content:RetentionDays' && (n < 6 || n > 30)) return 'Content retention must be between 6 and 30 days. There is no unlimited value.';
  }
  if (item.type === 'enum' && item.options && !item.options.includes(String(value))) return `Choose one of: ${item.options.join(', ')}.`;
  return undefined;
}

export function isKeepForever(item: SettingItem, value: DraftValue): boolean {
  return KEEP_FOREVER_KEYS.includes(item.key) && String(value).trim() === '0';
}

export function SettingField({ item, value, onChange, error }: { item: SettingItem; value: DraftValue; onChange: (v: DraftValue) => void; error?: string }) {
  const locked = !!item.locked;
  const hint = (
    <>
      {item.description}
      {locked && <> This value is set by deployment configuration and cannot be changed here.</>}
    </>
  );
  const label = item.key;

  if (item.type === 'boolean') {
    return (
      <div class="setting">
        <Field label={label} error={error} hint={hint}>
          {({ id, describedBy, invalid }) => (
            <div class="check">
              <input
                id={id}
                type="checkbox"
                checked={value === true}
                disabled={locked}
                aria-describedby={describedBy}
                aria-invalid={invalid || undefined}
                onChange={(e) => onChange((e.currentTarget as HTMLInputElement).checked)}
              />
              <span>{value === true ? 'Enabled' : 'Disabled'}</span>
              {locked && <Chip tone="neutral">Locked by deployment configuration</Chip>}
            </div>
          )}
        </Field>
      </div>
    );
  }

  return (
    <div class="setting">
      <Field label={label} error={error} hint={hint}>
        {({ id, describedBy, invalid }) => (
          <>
            {item.type === 'enum' ? (
              <select
                id={id}
                value={String(value ?? '')}
                disabled={locked}
                aria-describedby={describedBy}
                aria-invalid={invalid || undefined}
                onChange={(e) => onChange((e.currentTarget as HTMLSelectElement).value)}
              >
                {(item.options ?? []).map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
            ) : (
              <input
                id={id}
                type={item.type === 'number' ? 'number' : 'text'}
                min={item.type === 'number' ? 0 : undefined}
                inputMode={item.type === 'number' ? 'numeric' : undefined}
                value={String(value ?? '')}
                readOnly={locked}
                aria-describedby={describedBy}
                aria-invalid={invalid || undefined}
                onInput={(e) => onChange((e.currentTarget as HTMLInputElement).value)}
              />
            )}
            {locked && <Chip tone="neutral">Locked by deployment configuration</Chip>}
            {isKeepForever(item, value) && (
              <div class="notice notice-warn" role="status">
                0 keeps data forever; disk use grows without bound and cleanup is manual.
              </div>
            )}
          </>
        )}
      </Field>
    </div>
  );
}
