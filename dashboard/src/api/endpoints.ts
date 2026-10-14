import { http, itemsOf, setCsrfToken, request } from './client';
import type {
  AcmeRenewal,
  AdminStatus,
  ApiKey,
  CancelMessageResponse,
  Capabilities,
  CertificateInfo,
  CreateUserRequest,
  DashboardUser,
  DeliveryEvent,
  Domain,
  MaintenanceState,
  Me,
  MessageDetail,
  MessageQuery,
  MessageSummary,
  Page,
  PreflightReport,
  RecentEvent,
  ResendResponse,
  Role,
  SendMessageRequest,
  SendMessageResponse,
  SettingsResponse,
  SmtpCredential,
  StatsQuery,
  StatsResponse,
  StatsRow,
  Suppression,
  SwitchRequest,
  SwitchStartRequest,
  SwitchStatus,
  Tenant,
  Webhook,
  WebhookAttempt,
} from './types';

const enc = encodeURIComponent;

/** Typed wrappers for docs/api.md. Pages call these and never use fetch directly. */
export const api = {
  // ---- session ----
  capabilities: () => http.get<Capabilities>('/api/v1/capabilities'),
  async me(): Promise<Me> {
    const me = await request<Me>('GET', '/api/v1/me', { skipUnauthorizedHandler: true });
    setCsrfToken(me.csrfToken);
    return me;
  },
  async login(user: string, password: string): Promise<Me> {
    await http.post<{ user: string; role: string; tenantId: string | null }>('/api/v1/session', { user, password }, { skipUnauthorizedHandler: true });
    // /me returns the CSRF token to use for every mutating request.
    return api.me();
  },
  async logout(): Promise<void> {
    try {
      await http.del<void>('/api/v1/session');
    } finally {
      setCsrfToken(null);
    }
  },

  // ---- messages ----
  searchMessages: (q: MessageQuery) => http.get<Page<MessageSummary>>('/api/v1/messages', { ...q }),
  message: (id: string) => http.get<MessageDetail>(`/api/v1/messages/${enc(id)}`),
  messageEvents: async (id: string) => itemsOf(await http.get<DeliveryEvent[] | Page<DeliveryEvent>>(`/api/v1/messages/${enc(id)}/events`)),
  messageContent: (id: string) => http.get<{ text?: string; html?: string }>(`/api/v1/messages/${enc(id)}/content`),
  resend: (id: string) => http.post<ResendResponse>(`/api/v1/messages/${enc(id)}/resend`),
  cancelMessage: (id: string, recipients?: string[]) => http.post<CancelMessageResponse>(`/api/v1/messages/${enc(id)}/cancel`, recipients ? { recipients } : undefined),
  send: (body: SendMessageRequest, idempotencyKey?: string) =>
    http.post<SendMessageResponse>('/api/v1/messages', body, idempotencyKey ? { headers: { 'Idempotency-Key': idempotencyKey } } : undefined),

  // ---- domains ----
  domains: async () => itemsOf(await http.get<Domain[] | Page<Domain>>('/api/v1/domains')),
  domain: (id: string) => http.get<Domain>(`/api/v1/domains/${enc(id)}`),
  createDomain: (name: string) => http.post<Domain>('/api/v1/domains', { name }),
  deleteDomain: (id: string) => http.del<void>(`/api/v1/domains/${enc(id)}`),
  verifyDomain: (id: string) => http.post<Domain>(`/api/v1/domains/${enc(id)}/verify`),
  rotateDkim: (id: string) => http.post<Domain>(`/api/v1/domains/${enc(id)}/dkim/rotate`),
  cancelDkimRotation: (id: string) => http.del<Domain>(`/api/v1/domains/${enc(id)}/dkim/rotate`),

  // ---- suppressions ----
  suppressions: (cursor?: string, limit = 50) => http.get<Page<Suppression>>('/api/v1/suppressions', { cursor, limit }),
  addSuppression: (address: string, reason = 'manual') => http.post<Suppression>('/api/v1/suppressions', { address, reason }),
  removeSuppression: (address: string) => http.del<void>(`/api/v1/suppressions/${enc(address)}`),

  // ---- webhooks ----
  webhooks: async () => itemsOf(await http.get<Webhook[] | Page<Webhook>>('/api/v1/webhooks')),
  webhook: (id: string) => http.get<Webhook>(`/api/v1/webhooks/${enc(id)}`),
  createWebhook: (url: string, event_types: string[]) => http.post<Webhook>('/api/v1/webhooks', { url, event_types }),
  updateWebhook: (id: string, patch: Partial<Pick<Webhook, 'url' | 'event_types' | 'enabled'>>) => http.patch<Webhook>(`/api/v1/webhooks/${enc(id)}`, patch),
  deleteWebhook: (id: string) => http.del<void>(`/api/v1/webhooks/${enc(id)}`),
  rotateWebhookSecret: (id: string) => http.post<Webhook>(`/api/v1/webhooks/${enc(id)}/rotate-secret`),
  removePreviousWebhookSecret: (id: string) => http.del<void>(`/api/v1/webhooks/${enc(id)}/previous-secret`),
  testWebhook: (id: string) => http.post<{ outboxId?: string } | undefined>(`/api/v1/webhooks/${enc(id)}/test`),
  webhookAttempts: async (id: string, limit = 50) => itemsOf(await http.get<WebhookAttempt[] | Page<WebhookAttempt>>(`/api/v1/webhooks/${enc(id)}/attempts`, { limit })),
  replayWebhookEvent: (outboxId: string) => http.post<void>(`/api/v1/webhook-events/${enc(outboxId)}/replay`),

  // ---- credentials ----
  apiKeys: async () => itemsOf(await http.get<ApiKey[] | Page<ApiKey>>('/api/v1/api-keys')),
  createApiKey: (name: string, scopes: string[]) => http.post<ApiKey>('/api/v1/api-keys', { name, scopes }),
  revokeApiKey: (id: string) => http.del<void>(`/api/v1/api-keys/${enc(id)}`),
  smtpCredentials: async () => itemsOf(await http.get<SmtpCredential[] | Page<SmtpCredential>>('/api/v1/smtp-credentials')),
  createSmtpCredential: (username: string) => http.post<SmtpCredential>('/api/v1/smtp-credentials', { username }),
  revokeSmtpCredential: (id: string) => http.del<void>(`/api/v1/smtp-credentials/${enc(id)}`),

  // ---- statistics ----
  async stats(q: StatsQuery): Promise<StatsRow[]> {
    const r = await http.get<StatsRow[] | StatsResponse>('/api/v1/stats', { ...q });
    return Array.isArray(r) ? r : (r.rows ?? []);
  },
  recentEvents: async (limit = 50) => itemsOf(await http.get<RecentEvent[] | Page<RecentEvent>>('/api/v1/stats/recent-events', { limit })),

  // ---- tenant settings (see docs/components/dashboard.md, "API contract gaps") ----
  settings: () => http.get<SettingsResponse>('/api/v1/settings'),
  updateSettings: (values: Record<string, string | number | boolean | null>) => http.put<SettingsResponse>('/api/v1/settings', { values }),

  // ---- admin ----
  tenants: async () => itemsOf(await http.get<Tenant[] | Page<Tenant>>('/api/v1/admin/tenants')),
  createTenant: (name: string) => http.post<Tenant>('/api/v1/admin/tenants', { name }),
  updateTenant: (id: string, patch: Partial<Pick<Tenant, 'name' | 'status'>>) => http.patch<Tenant>(`/api/v1/admin/tenants/${enc(id)}`, patch),
  users: async () => itemsOf(await http.get<DashboardUser[] | Page<DashboardUser>>('/api/v1/admin/users')),
  createUser: (body: CreateUserRequest) => http.post<DashboardUser>('/api/v1/admin/users', body),
  updateUser: (id: string, patch: { enabled?: boolean; role?: Role; tenantId?: string }) => http.patch<DashboardUser>(`/api/v1/admin/users/${enc(id)}`, patch),
  deleteUser: (id: string) => http.del<void>(`/api/v1/admin/users/${enc(id)}`),
  /** Without `password` the server generates one and returns it once. */
  resetUserPassword: (id: string, password?: string) => http.post<DashboardUser>(`/api/v1/admin/users/${enc(id)}/reset-password`, password === undefined ? {} : { password }),
  /** The signed-in user's own password. The other sessions of the user end; this one stays. */
  changePassword: (currentPassword: string, newPassword: string) => http.post<void>('/api/v1/me/password', { currentPassword, newPassword }),
  adminStatus: () => http.get<AdminStatus>('/api/v1/admin/status'),
  adminSettings: () => http.get<SettingsResponse>('/api/v1/admin/settings'),
  updateAdminSettings: (values: Record<string, string | number | boolean | null>) => http.put<SettingsResponse>('/api/v1/admin/settings', { values }),
  certificates: async () => itemsOf(await http.get<CertificateInfo[] | Page<CertificateInfo>>('/api/v1/admin/certificates')),
  uploadCertificate: (body: { certificatePem?: string; privateKeyPem?: string; pfxBase64?: string; pfxPassword?: string }) =>
    http.post<CertificateInfo>('/api/v1/admin/certificates', body),
  requestAcmeCertificate: (domains: string[]) => http.post<{ status: string; message?: string }>('/api/v1/admin/certificates/acme', { domains }),
  acmeRenewals: async () => itemsOf(await http.get<AcmeRenewal[] | Page<AcmeRenewal>>('/api/v1/admin/certificates/acme')),
  runMaintenance: () => http.post<{ status?: string } | undefined>('/api/v1/admin/maintenance/run'),
  maintenance: () => http.get<MaintenanceState>('/api/v1/admin/maintenance'),

  // ---- storage switch (never automatic) ----
  switchPreflight: (body: SwitchRequest) => http.post<PreflightReport>('/api/v1/admin/storage/switch/preflight', body),
  switchStart: (body: SwitchStartRequest) => http.post<SwitchStatus>('/api/v1/admin/storage/switch/start', body),
  switchStatus: () => http.get<SwitchStatus>('/api/v1/admin/storage/switch'),
  switchConfirm: () => http.post<SwitchStatus>('/api/v1/admin/storage/switch/confirm'),
  switchActivate: () => http.post<SwitchStatus>('/api/v1/admin/storage/switch/activate'),
  switchRollback: () => http.post<SwitchStatus>('/api/v1/admin/storage/switch/rollback'),
  switchFinalize: () => http.post<SwitchStatus>('/api/v1/admin/storage/switch/finalize'),
};
