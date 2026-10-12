import { useEffect, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { fieldErrors } from '../api/errorMessages';
import type { SettingItem, SettingsResponse } from '../api/types';
import { SettingField, validateSetting } from '../components/SettingField';
import type { DraftValue } from '../components/SettingField';
import { Button, Card, EmptyState, ErrorNotice, Loading, Notice, PageHeader } from '../components/ui';
import { useAction, useApi, useDocumentTitle } from '../lib/hooks';
import { useApp } from '../state/app';

type Values = Record<string, string | number | boolean | null>;

function toDraft(items: SettingItem[]): Record<string, DraftValue> {
  return Object.fromEntries(items.map((i) => [i.key, i.value]));
}

function SettingsSection({
  title,
  description,
  load,
  save,
}: {
  title: string;
  description: string;
  load: () => Promise<SettingsResponse>;
  save: (values: Values) => Promise<SettingsResponse>;
}) {
  const { data, error, loading, reload } = useApi(load, []);
  const [items, setItems] = useState<SettingItem[]>([]);
  const [draft, setDraft] = useState<Record<string, DraftValue>>({});
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState<string | null>(null);

  useEffect(() => {
    if (data) {
      setItems(data.items);
      setDraft(toDraft(data.items));
    }
  }, [data]);

  const submit = useAction(async (values: Values) => save(values));
  const serverErrors = fieldErrors(submit.error);

  const changedKeys = items.filter((i) => !i.locked && String(draft[i.key] ?? '') !== String(i.value ?? '')).map((i) => i.key);

  const onSubmit = async (e: Event) => {
    e.preventDefault();
    setSaved(null);
    const errs: Record<string, string> = {};
    const values: Values = {};
    for (const key of changedKeys) {
      const item = items.find((i) => i.key === key)!;
      const problem = validateSetting(item, draft[key]);
      if (problem) errs[key] = problem;
      else values[key] = item.type === 'number' ? Number(draft[key]) : (draft[key] as Values[string]);
    }
    setClientErrors(errs);
    if (Object.keys(errs).length || !changedKeys.length) return;
    const res = await submit.run(values);
    if (res) {
      setItems(res.items);
      setDraft(toDraft(res.items));
      setSaved(`Saved ${changedKeys.length} setting${changedKeys.length === 1 ? '' : 's'}.`);
    }
  };

  return (
    <Card title={title}>
      <p class="muted">{description}</p>
      {loading && !data && <Loading />}
      {error !== undefined && <ErrorNotice error={error} onRetry={reload} />}
      {data && items.length === 0 && <EmptyState title="No settings">There are no settings to show.</EmptyState>}
      {items.length > 0 && (
        <form class="stack" onSubmit={onSubmit} noValidate aria-label={title}>
          {items.some((i) => i.locked) && (
            <Notice tone="info">Settings marked as locked come from deployment configuration (command line, environment or mounted files) and cannot be edited here.</Notice>
          )}
          {items.map((i) => (
            <SettingField
              key={i.key}
              item={i}
              value={draft[i.key] ?? ''}
              error={clientErrors[i.key] ?? serverErrors[i.key]}
              onChange={(v) => {
                setSaved(null);
                setClientErrors((prev) => ({ ...prev, [i.key]: '' }));
                setDraft((prev) => ({ ...prev, [i.key]: v }));
              }}
            />
          ))}
          {submit.error !== undefined && Object.keys(serverErrors).length === 0 && <ErrorNotice error={submit.error} />}
          {saved && (
            <div class="notice notice-ok" role="status">
              {saved}
            </div>
          )}
          <div class="row">
            <Button type="submit" variant="primary" busy={submit.busy} disabled={changedKeys.length === 0}>
              Save settings
            </Button>
            {changedKeys.length > 0 && <span class="muted small">{changedKeys.length} unsaved change{changedKeys.length === 1 ? '' : 's'}</span>}
          </div>
        </form>
      )}
    </Card>
  );
}

export default function Settings(_props: Record<string, unknown>) {
  useDocumentTitle('Settings');
  const { isAdmin } = useApp();
  return (
    <>
      <PageHeader title="Settings" subtitle="The same settings apply on every storage backend." />
      <SettingsSection title="Tenant settings" description="Settings for the tenant you are acting on." load={() => api.settings()} save={(v) => api.updateSettings(v)} />
      {isAdmin && (
        <SettingsSection
          title="Global settings"
          description="Server-wide settings, visible to administrators only. A locked value is fixed by deployment configuration."
          load={() => api.adminSettings()}
          save={(v) => api.updateAdminSettings(v)}
        />
      )}
    </>
  );
}
