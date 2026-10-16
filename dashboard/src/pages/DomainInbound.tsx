import { useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { fieldErrors } from '../api/errorMessages';
import type { InboundRoute, InboundRouteProbe, InboundSettings, Webhook } from '../api/types';
import { RecordStatusChip } from '../components/DnsRecordsTable';
import { Button, Card, CheckField, Chip, ConfirmDialog, CopyButton, Dialog, EmptyState, ErrorNotice, Field, Loading, Notice, PageHeader, TextField } from '../components/ui';
import { useAction, useApi, useDocumentTitle } from '../lib/hooks';
import {
  ACTION_KINDS,
  DMARC_ACTIONS,
  MATCH_KINDS,
  describeAction,
  describeMatch,
  effectiveText,
  emptyRouteForm,
  routeRequest,
  routeToForm,
  settingsPatch,
  settingsToForm,
  validateRoute,
  validateSettings,
} from '../lib/inbound';
import type { RouteErrors, RouteForm, SettingsErrors, SettingsForm } from '../lib/inbound';
import { useApp } from '../state/app';

/* ---------- settings ---------- */

function SettingsCard({ domainId, settings, onSaved }: { domainId: string; settings: InboundSettings; onSaved: (s: InboundSettings) => void }) {
  const [form, setForm] = useState<SettingsForm>(() => settingsToForm(settings));
  const [errors, setErrors] = useState<SettingsErrors>({});
  const [saved, setSaved] = useState(false);
  const save = useAction(async (patch: ReturnType<typeof settingsPatch>) => {
    const s = await api.updateInboundSettings(domainId, patch);
    onSaved(s);
    setForm(settingsToForm(s));
    setSaved(true);
    return s;
  });
  const set = <K extends keyof SettingsForm>(k: K) => (v: SettingsForm[K]) => {
    setSaved(false);
    setForm((f) => ({ ...f, [k]: v }));
  };
  const server = fieldErrors(save.error);
  const patch = settingsPatch(settings, form);
  const dirty = Object.keys(patch).length > 0;
  const eff = settings.effective;
  const action = DMARC_ACTIONS.find((a) => a.value === form.dmarcAction);

  const submit = async (e: Event) => {
    e.preventDefault();
    const found = validateSettings(form);
    setErrors(found);
    if (Object.keys(found).length > 0 || !dirty) return;
    await save.run(patch);
  };

  return (
    <Card title="Settings">
      <form class="stack" onSubmit={submit} aria-label="Inbound settings" noValidate>
        <CheckField
          label="Receive mail for this domain"
          hint="The server accepts mail for the addresses your routes handle and refuses everything else. The domain must be verified."
          checked={form.enabled}
          onChange={set('enabled')}
        />
        <Field label="When a message fails DMARC" hint={action?.help}>
          {({ id, describedBy }) => (
            <select id={id} aria-describedby={describedBy} value={form.dmarcAction} onChange={(e) => set('dmarcAction')((e.currentTarget as HTMLSelectElement).value as SettingsForm['dmarcAction'])}>
              {DMARC_ACTIONS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </select>
          )}
        </Field>
        <div class="form-grid">
          <TextField
            label="Largest message (MiB)"
            value={form.maxMessageMiB}
            onInput={set('maxMessageMiB')}
            error={errors.maxMessageMiB ?? server.maxMessageBytes}
            placeholder={effectiveText('bytes', eff.maxMessageBytes).replace(' MiB', '')}
            hint={`Empty: the server value (${effectiveText('bytes', eff.maxMessageBytes)} applies). You can only lower it.`}
            inputMode="decimal"
            autocomplete="off"
          />
          <TextField
            label="Messages per minute"
            value={form.maxMessagesPerMinute}
            onInput={set('maxMessagesPerMinute')}
            error={errors.maxMessagesPerMinute ?? server.maxMessagesPerMinute}
            placeholder={String(eff.maxMessagesPerMinute)}
            hint={`Empty: the server value (${eff.maxMessagesPerMinute}). For the whole domain.`}
            inputMode="numeric"
            autocomplete="off"
          />
          <TextField
            label="Messages per minute from one sender address"
            value={form.maxMessagesPerMinutePerRemote}
            onInput={set('maxMessagesPerMinutePerRemote')}
            error={errors.maxMessagesPerMinutePerRemote ?? server.maxMessagesPerMinutePerRemote}
            placeholder={String(eff.maxMessagesPerMinutePerRemote)}
            hint={`Empty: the server value (${eff.maxMessagesPerMinutePerRemote}).`}
            inputMode="numeric"
            autocomplete="off"
          />
          <TextField
            label="Stored mail limit (MiB)"
            value={form.maxStoredMiB}
            onInput={set('maxStoredMiB')}
            error={errors.maxStoredMiB ?? server.maxStoredBytes}
            placeholder={eff.maxStoredBytes === 0 ? '0' : effectiveText('storedBytes', eff.maxStoredBytes).replace(' MiB', '')}
            hint={`Empty: the server value (${effectiveText('storedBytes', eff.maxStoredBytes)}). At the limit senders are told to retry later (452). 0 is unlimited.`}
            inputMode="decimal"
            autocomplete="off"
          />
          <TextField
            label="Keep received mail (days)"
            value={form.retentionDays}
            onInput={set('retentionDays')}
            error={errors.retentionDays ?? server.retentionDays}
            placeholder={String(eff.retentionDays)}
            hint={`Empty: the server value (${effectiveText('days', eff.retentionDays)}). 0 keeps messages forever.`}
            inputMode="numeric"
            autocomplete="off"
          />
        </div>
        {form.retentionDays.trim() === '0' && (
          <Notice tone="warn" title="Messages are kept forever">
            Received mail is personal data. Without an end date the stored mail grows until the stored mail limit is reached; make sure that is what you want.
          </Notice>
        )}
        {settings.warnings?.map((w) => (
          <Notice key={w.code} tone="warn">
            {w.message}
          </Notice>
        ))}
        {save.error !== undefined && <ErrorNotice error={save.error} title="The settings were not saved" />}
        {saved && <Notice tone="ok">Settings saved.</Notice>}
        <div class="row">
          <Button type="submit" variant="primary" busy={save.busy} disabled={!dirty}>
            Save settings
          </Button>
        </div>
      </form>
    </Card>
  );
}

/* ---------- DNS guidance ---------- */

function MxCard({ domainName, settings }: { domainName: string; settings: InboundSettings }) {
  const host = settings.mx.host;
  return (
    <Card title="DNS: where senders deliver">
      {!host ? (
        <Notice tone="warn">This server has no fully qualified host name configured (<code>Hostname</code>), so there is no MX record to suggest yet. Ask the operator.</Notice>
      ) : (
        <div class="stack">
          <p>
            Publish this record so that other servers deliver the mail of <strong>{domainName}</strong> here:
          </p>
          <div class="table-wrap">
            <table class="dns-table">
              <caption class="sr-only">MX record to publish</caption>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Host</th>
                  <th scope="col">Value</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <code>MX</code>
                  </td>
                  <td>
                    <code data-testid="mx-host">{domainName}</code> <CopyButton text={domainName} what="MX host" />
                  </td>
                  <td>
                    <code data-testid="mx-value">{`${settings.mx.priority} ${host}`}</code> <CopyButton text={`${settings.mx.priority} ${host}`} what="MX value" />
                  </td>
                  <td>{settings.mx.status ? <RecordStatusChip status={settings.mx.status} /> : <Chip>Not checked</Chip>}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <ul class="dns-hints">
            <li>
              Replace the domain's existing MX records, or give this one the lowest preference number to make it the first choice. Other MX records keep receiving mail until you remove them.
            </li>
            <li>
              <code>{host}</code> needs an <code>A</code> or <code>AAAA</code> record, and <strong>port 25 must be reachable from the Internet</strong> (many hosting providers and home networks block it).
            </li>
            <li>
              If you publish MTA-STS or TLS-RPT for this domain, the <code>mx:</code> line of the policy has to name <code>{host}</code> too, or senders that enforce the policy will refuse to deliver. STARTTLS is offered, never required, unless a policy says so.
            </li>
            <li>
              The status is checked with <strong>Check DNS</strong> on the <a href={`/domains/${settings.domainId}`}>domain page</a>.
            </li>
          </ul>
        </div>
      )}
    </Card>
  );
}

/* ---------- routes ---------- */

function RouteDialog({
  domainId,
  route,
  endpoints,
  onClose,
  onSaved,
}: {
  domainId: string;
  route: InboundRoute | null;
  endpoints: Webhook[];
  onClose: () => void;
  onSaved: (r: InboundRoute) => void;
}) {
  const [form, setForm] = useState<RouteForm>(() => (route ? routeToForm(route) : emptyRouteForm));
  const [errors, setErrors] = useState<RouteErrors>({});
  const save = useAction(async () => {
    const body = routeRequest(form);
    const saved = route ? await api.updateInboundRoute(domainId, route.id, body) : await api.createInboundRoute(domainId, body);
    onSaved(saved);
    return saved;
  });
  const set = <K extends keyof RouteForm>(k: K) => (v: RouteForm[K]) => setForm((f) => ({ ...f, [k]: v }));
  const server = fieldErrors(save.error);
  const serverFor = (...names: string[]) => names.map((n) => server[n]).find(Boolean);
  const kind = ACTION_KINDS.find((a) => a.value === form.actionKind);

  const submit = async (e: Event) => {
    e.preventDefault();
    const found = validateRoute(form);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    await save.run();
  };

  return (
    <Dialog title={route ? 'Edit route' : 'Add route'} onClose={onClose}>
      <form class="stack" onSubmit={submit} noValidate aria-label="Route">
        <TextField label="Name" value={form.name} onInput={set('name')} error={errors.name ?? server.name} hint="For you only; optional." autocomplete="off" />
        <div class="form-grid">
          <Field label="Matches">
            {({ id }) => (
              <select id={id} value={form.matchKind} onChange={(e) => set('matchKind')((e.currentTarget as HTMLSelectElement).value as RouteForm['matchKind'])}>
                {MATCH_KINDS.map((m) => (
                  <option key={m.value} value={m.value}>
                    {m.label}
                  </option>
                ))}
              </select>
            )}
          </Field>
          {form.matchKind !== 'catch_all' && (
            <TextField
              label={form.matchKind === 'wildcard' ? 'Pattern (before the @)' : 'Address (before the @)'}
              value={form.localPart}
              onInput={set('localPart')}
              error={errors.localPart ?? serverFor('match.localPart')}
              placeholder={form.matchKind === 'wildcard' ? 'billing-*' : 'support'}
              hint="Capitals do not matter."
              autocomplete="off"
              spellcheck={false}
            />
          )}
        </div>
        {form.matchKind !== 'catch_all' && (
          <CheckField
            label="Also match name+anything"
            hint="support+billing@ reaches the route for support@, unless a route for support+billing comes first."
            checked={form.plusAddressing}
            onChange={set('plusAddressing')}
          />
        )}
        <TextField
          label="Order"
          value={form.order}
          onInput={set('order')}
          error={errors.order ?? server.order}
          hint="The first enabled route that matches wins; the lowest number is checked first. Put a catch-all last."
          inputMode="numeric"
          autocomplete="off"
        />
        <Field label="Then" hint={kind?.help}>
          {({ id, describedBy }) => (
            <select id={id} aria-describedby={describedBy} value={form.actionKind} onChange={(e) => set('actionKind')((e.currentTarget as HTMLSelectElement).value as RouteForm['actionKind'])}>
              {ACTION_KINDS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </select>
          )}
        </Field>
        {form.actionKind === 'webhook' && (
          <>
            <Field label="Webhook endpoint" error={errors.webhookEndpointId ?? serverFor('action.webhookEndpointId')}>
              {({ id, describedBy, invalid }) => (
                <select id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} value={form.webhookEndpointId} onChange={(e) => set('webhookEndpointId')((e.currentTarget as HTMLSelectElement).value)}>
                  <option value="">Choose an endpoint</option>
                  {endpoints.map((w) => (
                    <option key={w.id} value={w.id}>
                      {w.url}
                      {w.enabled ? '' : ' (disabled)'}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <Field
              label="Format"
              hint={form.webhookFormat === 'json' ? 'A JSON document with the envelope, the verdicts, the text and HTML (cut when large) and the attachments listed by reference.' : 'The message itself (message/rfc822) with the envelope in headers; limited in size.'}
            >
              {({ id, describedBy }) => (
                <select id={id} aria-describedby={describedBy} value={form.webhookFormat} onChange={(e) => set('webhookFormat')((e.currentTarget as HTMLSelectElement).value as RouteForm['webhookFormat'])}>
                  <option value="json">JSON</option>
                  <option value="raw_mime">Raw message</option>
                </select>
              )}
            </Field>
          </>
        )}
        {form.actionKind === 'forward' && (
          <Field
            label="Forward to"
            error={errors.forwardTo ?? serverFor('action.forwardTo', ...Array.from({ length: 10 }, (_, i) => `action.forwardTo[${i}]`))}
            hint="One to ten addresses, one per line. They cannot be in a domain this server receives for (that would loop)."
          >
            {({ id, describedBy, invalid }) => (
              <textarea id={id} rows={3} aria-describedby={describedBy} aria-invalid={invalid || undefined} value={form.forwardTo} onInput={(e) => set('forwardTo')((e.currentTarget as HTMLTextAreaElement).value)} spellcheck={false} />
            )}
          </Field>
        )}
        <CheckField label="Enabled" hint="A disabled route is skipped for new mail; messages already waiting for it are still served." checked={form.enabled} onChange={set('enabled')} />
        {save.error !== undefined && <ErrorNotice error={save.error} title="The route was not saved" />}
        <div class="row end">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.busy}>
            {route ? 'Save route' : 'Add route'}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function RoutesCard({ domainId, enabled }: { domainId: string; enabled: boolean }) {
  const routes = useApi(() => api.inboundRoutes(domainId), [domainId]);
  const hooks = useApi(() => api.webhooks(), []);
  const [editing, setEditing] = useState<InboundRoute | 'new' | null>(null);
  const [deleting, setDeleting] = useState<InboundRoute | null>(null);
  const [warnings, setWarnings] = useState<{ route: string; code: string; message: string }[]>([]);
  const remove = useAction(async (r: InboundRoute) => {
    await api.deleteInboundRoute(domainId, r.id);
    setDeleting(null);
    routes.reload();
  });
  const toggle = useAction(async (r: InboundRoute) => {
    await api.updateInboundRoute(domainId, r.id, { enabled: !r.enabled });
    routes.reload();
  });
  const endpointUrl = (id?: string | null) => hooks.data?.find((w) => w.id === id)?.url;
  const list = routes.data ? [...routes.data].sort((a, b) => a.order - b.order || a.createdAt.localeCompare(b.createdAt)) : [];

  return (
    <Card
      title="Routes"
      id="routes"
      actions={
        <Button variant="primary" onClick={() => setEditing('new')}>
          Add route
        </Button>
      }
    >
      <p class="muted">
        A message is handled by the <strong>first enabled route that matches</strong> its recipient, from the lowest order. A recipient no route matches is refused, except <code>postmaster</code>, which is always accepted and stored.
      </p>
      {!enabled && <Notice tone="info">Receiving is off for this domain: routes are prepared but no mail arrives until you turn it on above.</Notice>}
      {routes.loading && !routes.data && <Loading label="Loading routes" />}
      {routes.error !== undefined && <ErrorNotice error={routes.error} onRetry={routes.reload} />}
      {toggle.error !== undefined && <ErrorNotice error={toggle.error} />}
      {warnings.map((w) => (
        <Notice key={`${w.route}-${w.code}`} tone="warn" title={`Route ${w.route}`}>
          {w.message}
        </Notice>
      ))}
      {routes.data && list.length === 0 && (
        <EmptyState title="No routes yet">
          <p>Add a route to start receiving. A catch-all route with the action Store keeps everything sent to the domain.</p>
        </EmptyState>
      )}
      {list.length > 0 && (
        <div class="table-wrap">
          <table>
            <caption class="sr-only">Routes in the order they are checked</caption>
            <thead>
              <tr>
                <th scope="col" class="num">
                  Order
                </th>
                <th scope="col">Name</th>
                <th scope="col">Matches</th>
                <th scope="col">Action</th>
                <th scope="col">State</th>
                <th scope="col">
                  <span class="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.map((r) => (
                <tr key={r.id}>
                  <td class="num">{r.order}</td>
                  <td class="wrap">{r.name || <span class="muted">(no name)</span>}</td>
                  <td class="wrap">
                    <code>{describeMatch(r)}</code>
                  </td>
                  <td class="wrap">{describeAction(r, endpointUrl(r.action.webhookEndpointId))}</td>
                  <td>{r.enabled ? <Chip tone="ok">Enabled</Chip> : <Chip>Disabled</Chip>}</td>
                  <td>
                    <div class="row">
                      <Button class="btn-small" onClick={() => setEditing(r)} aria-label={`Edit route ${r.name || describeMatch(r)}`}>
                        Edit
                      </Button>
                      <Button class="btn-small" onClick={() => void toggle.run(r)} busy={toggle.busy} aria-label={`${r.enabled ? 'Disable' : 'Enable'} route ${r.name || describeMatch(r)}`}>
                        {r.enabled ? 'Disable' : 'Enable'}
                      </Button>
                      <Button class="btn-small" variant="danger" onClick={() => setDeleting(r)} aria-label={`Delete route ${r.name || describeMatch(r)}`}>
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editing && (
        <RouteDialog
          domainId={domainId}
          route={editing === 'new' ? null : editing}
          endpoints={hooks.data ?? []}
          onClose={() => setEditing(null)}
          onSaved={(r) => {
            setEditing(null);
            setWarnings((w) => [...w.filter((x) => x.route !== (r.name || r.id)), ...(r.warnings ?? []).map((x) => ({ route: r.name || describeMatch(r), ...x }))]);
            routes.reload();
          }}
        />
      )}
      {deleting && (
        <ConfirmDialog title="Delete this route?" confirmLabel="Delete route" busy={remove.busy} error={remove.error} onCancel={() => setDeleting(null)} onConfirm={() => void remove.run(deleting)}>
          <p>
            Mail for <code>{describeMatch(deleting)}</code> is refused from now on unless another route matches. Messages already received for it keep waiting, but their action fails.
          </p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

/* ---------- route test ---------- */

function ProbeCard({ domainId, domainName }: { domainId: string; domainName: string }) {
  const [local, setLocal] = useState('');
  const [result, setResult] = useState<InboundRouteProbe | null>(null);
  const probe = useAction(async () => {
    const r = await api.probeInboundRoute(domainId, `${local.trim()}@${domainName}`);
    setResult(r);
    return r;
  });
  const replyText = (r: InboundRouteProbe) => {
    switch (r.reply) {
      case '250':
        return 'accepted';
      case '550 5.1.1':
        return 'refused: no route handles this address';
      case '550 5.7.1':
        return 'refused: this domain does not receive mail';
      case '450 4.2.1':
        return 'asked to try again later: the domain is not verified at the moment, or the tenant is suspended';
      default:
        return r.reply;
    }
  };
  return (
    <Card title="Try an address">
      <form
        class="stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (local.trim()) void probe.run();
        }}
        aria-label="Try an address"
      >
        <div class="row">
          <TextField label="Address" value={local} onInput={setLocal} placeholder="support" autocomplete="off" spellcheck={false} hint={`at @${domainName}; nothing is sent or stored`} />
          <Button type="submit" busy={probe.busy} disabled={!local.trim()}>
            Test
          </Button>
        </div>
        {probe.error !== undefined && <ErrorNotice error={probe.error} />}
        {result && (
          <div role="status" data-testid="probe-result">
            <p>
              <strong>{result.address}</strong>: {replyText(result)} <code>{result.reply}</code>
            </p>
            {result.route && (
              <p>
                Handled by route <strong>{result.route.name || describeMatch(result.route)}</strong> ({describeAction(result.route)}).
              </p>
            )}
          </div>
        )}
      </form>
    </Card>
  );
}

/* ---------- page ---------- */

export default function DomainInbound({ id }: { id?: string }) {
  const domainId = id ?? '';
  const { capabilities } = useApp();
  const domain = useApi(() => api.domain(domainId), [domainId]);
  const settings = useApi(() => api.inboundSettings(domainId), [domainId]);
  useDocumentTitle(domain.data ? `Inbound mail - ${domain.data.name}` : 'Inbound mail');

  const serverOff = !!capabilities && !capabilities.inbound?.enabled;
  if ((domain.loading && !domain.data) || (settings.loading && !settings.data)) return <Loading label="Loading inbound settings" />;
  if (domain.error !== undefined) return <ErrorNotice error={domain.error} onRetry={domain.reload} />;
  if (settings.error !== undefined) return <ErrorNotice error={settings.error} onRetry={settings.reload} />;
  if (!domain.data || !settings.data) return null;

  return (
    <>
      <PageHeader
        title={`Inbound mail: ${domain.data.name}`}
        subtitle={
          <>
            <a href={`/domains/${domainId}`}>Back to the domain</a> · <a href="/inbound">Received messages</a>
          </>
        }
        actions={settings.data.enabled ? <Chip tone="ok">Receiving</Chip> : <Chip>Off</Chip>}
      />
      {serverOff && (
        <Notice tone="warn" title="Inbound mail is not enabled on this server">
          The operator switches it on with <code>Inbound:Enabled</code>. You can prepare the settings and routes now; no mail is received until then.
        </Notice>
      )}
      {domain.data.status !== 'verified' && domain.data.status !== 'temporary_failure' && (
        <Notice tone="warn" title="The domain is not verified">
          A domain can receive mail only after its DNS records are verified: otherwise whoever points an MX record at this server could read its mail. Verify it on the{' '}
          <a href={`/domains/${domainId}`}>domain page</a> first.
        </Notice>
      )}
      <SettingsCard domainId={domainId} settings={settings.data} onSaved={(s) => settings.setData(s)} />
      <MxCard domainName={domain.data.name} settings={settings.data} />
      <RoutesCard domainId={domainId} enabled={settings.data.enabled} />
      <ProbeCard domainId={domainId} domainName={domain.data.name} />
    </>
  );
}
