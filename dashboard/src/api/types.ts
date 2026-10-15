// Wire types for the EggMail HTTP API v1 (docs/api.md). Where the contract leaves a response shape
// open, the shape used here is listed in docs/components/dashboard.md ("API contract gaps").
// Clients must ignore unknown response members, so every interface only lists what the UI uses.

export type Role = 'admin' | 'tenant';
export type HistoryMode = 'full' | 'statsonly';

export interface Me {
  user: string;
  role: Role;
  tenantId: string | null;
  /** CSRF token for mutating requests (also accepted from the X-CSRF-Token response header). */
  csrfToken?: string;
  /** The user signed in with a temporary password (the generated one of the first administrator): only changing it, and signing out, are allowed until then. */
  mustChangePassword?: boolean;
}

export interface CapabilityWarning {
  code: string;
  message: string;
}

export interface Capabilities {
  version: string;
  /** Informational only. The UI never branches on this for features. */
  backend: string;
  history: { mode: HistoryMode };
  content: { retentionDays: number; storeAttachments: boolean };
  limits: { maxMessageBytes: number; maxRecipients: number };
  warnings: CapabilityWarning[];
}

export interface FieldError {
  field: string;
  message: string;
}

export interface Problem {
  type?: string;
  title?: string;
  status: number;
  detail?: string;
  code?: string;
  request_id?: string;
  errors?: FieldError[];
  [extra: string]: unknown;
}

export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}

// ---- messages ----

export type MessageStatus =
  | 'queued'
  | 'delivered'
  | 'deferred'
  | 'bounced'
  | 'expired'
  | 'suppressed'
  | 'cancelled'
  | 'complained'
  | string;

export interface MessageSummary {
  id: string;
  receivedAt: string;
  subject: string;
  from: string;
  recipients: string[];
  /** All recipients; `recipients` holds only the first few in a list. */
  recipientCount?: number;
  status: MessageStatus;
  size: number;
  tags?: string[];
}

export interface AttachmentInfo {
  filename: string;
  content_type?: string;
  contentType?: string;
  size?: number;
  content_id?: string | null;
}

export interface MessageDetail extends MessageSummary {
  tenantId: string;
  content: {
    state: 'available' | 'body_expired' | 'not_recorded';
    text?: string;
    html?: string;
    attachments: AttachmentInfo[];
    /** The stored text or HTML was cut at the size limit. */
    truncated?: boolean;
  };
  rawRetained: boolean;
}

export type DeliveryEventType =
  | 'queued'
  | 'delivered'
  | 'deferred'
  | 'bounced'
  | 'expired'
  | 'suppressed'
  | 'cancelled'
  | 'complained'
  | 'aborted_by_switch'
  | 'possible_duplicate'
  | string;

export interface TlsDetails {
  used?: boolean;
  version?: string;
  cipher?: string;
  verified?: boolean;
  policy?: string;
  peerSubject?: string;
  peerIssuer?: string;
  peerSha256?: string;
  [extra: string]: unknown;
}

export interface DeliveryEvent {
  id: string;
  type: DeliveryEventType;
  at: string;
  recipient?: string | null;
  smtpCode?: number | null;
  enhancedCode?: string | null;
  message?: string | null;
  mxHost?: string | null;
  route?: string | null;
  tls?: TlsDetails | null;
}

export interface MessageQuery {
  recipient?: string;
  sender?: string;
  subject?: string;
  status?: string;
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string;
}

export interface SendMessageRequest {
  from: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  reply_to?: string;
  subject: string;
  text?: string;
  html?: string;
  headers?: Record<string, string>;
  attachments?: { filename: string; content_type: string; content: string; content_id?: string | null }[];
  store_attachments?: boolean;
  tags?: string[];
}

export interface SendMessageResponse {
  id: string;
  status: string;
  recipients: number;
}

export interface ResendResponse {
  id: string;
  recomposed?: boolean;
}

/** POST /messages/{id}/cancel: what happened to each recipient that was named (or, without names, to each one still waiting). */
export interface CancelMessageResponse {
  id: string;
  /** The message status after the cancel; absent when the server does not record per-message history. */
  status?: MessageStatus;
  cancelled: string[];
  /** Waiting recipients that a delivery attempt holds right now: left alone, they finish normally. */
  inFlight: string[];
  /** Waiting recipients that a storage backend switch holds: left alone until the switch is finished or rolled back. */
  transferHeld: string[];
  /** Named recipients that were not waiting (already finished, or not recipients of this message). */
  notWaiting: string[];
}

// ---- domains ----

export type DomainStatus = 'pending' | 'verifying' | 'verified' | 'temporary_failure' | 'failed';
export type RecordPurpose = 'dkim' | 'return_path' | 'spf' | 'dmarc';
export type RecordStatus = 'ok' | 'missing' | 'invalid' | 'pending';

export interface DnsRecord {
  type: string;
  host: string;
  value: string;
  ttl: number;
  purpose: RecordPurpose;
  status: RecordStatus;
  found?: string | null;
  expected?: string;
}

/** One DKIM key of a domain: `active` keys sign; a key that is neither active nor retired is a pending rotation (published as advice, not signing yet). */
export interface DkimKeyInfo {
  selector: string;
  publicKey: string;
  active: boolean;
  createdAt: string;
  retiredAt?: string | null;
}

export interface Domain {
  id: string;
  name: string;
  status: DomainStatus;
  sendingPaused: boolean;
  lastCheckedAt?: string | null;
  nextCheckAt?: string | null;
  lastError?: string | null;
  records: DnsRecord[];
  /** The newest key (which may be a pending rotation). */
  dkim: DkimKeyInfo;
  /** Every key, oldest first. Absent in older servers and fixtures. */
  dkimKeys?: DkimKeyInfo[];
}

// ---- suppressions ----

export interface Suppression {
  address: string;
  reason: string;
  createdAt?: string;
}

// ---- webhooks ----

export interface Webhook {
  id: string;
  url: string;
  event_types: string[];
  enabled: boolean;
  disabledReason?: string | null;
  disabledAt?: string | null;
  createdAt?: string;
  /** True after a secret rotation until the previous secret is removed (deliveries are signed with both). */
  secretRotationPending?: boolean;
  /** Present only in the create and rotate-secret responses. */
  secret?: string;
}

export interface WebhookAttempt {
  id: string;
  outboxId: string;
  eventType?: string;
  at: string;
  status: number | null;
  durationMs: number;
  errorClass?: string | null;
  snippet?: string | null;
}

// ---- credentials ----

export interface ApiKey {
  id: string;
  name: string;
  prefix?: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt?: string | null;
  /** Present only in the create response. */
  key?: string;
}

export interface SmtpCredential {
  id: string;
  username: string;
  createdAt: string;
  /** Present only in the create response. */
  password?: string;
}

export const API_KEY_SCOPES = ['send', 'read', 'domains', 'webhooks', 'suppressions', 'keys'] as const;

// ---- statistics ----

export interface StatsRow {
  period: string;
  sendingDomain?: string;
  recipientDomain?: string;
  accepted: number;
  delivered: number;
  deferred: number;
  hardBounce: number;
  softBounce: number;
  expired: number;
  complained: number;
  rejected: number;
  suppressed: number;
}

export interface StatsResponse {
  granularity?: 'hour' | 'day';
  rows: StatsRow[];
}

export interface StatsQuery {
  from?: string;
  to?: string;
  granularity?: 'hour' | 'day';
  domain?: string;
}

export interface RecentEvent {
  at: string;
  type: string;
  recipientDomain?: string;
  sendingDomain?: string;
  tenantId?: string;
  code?: string | null;
}

// ---- tenant settings and admin ----

export interface SettingItem {
  key: string;
  value: string | number | boolean | null;
  type?: 'string' | 'number' | 'boolean' | 'enum';
  options?: string[];
  description?: string;
  /** Set from deployment configuration; shown read-only. */
  locked?: boolean;
  /** The stored value is read at the next start of the server. */
  requiresRestart?: boolean;
}

export interface SettingsResponse {
  items: SettingItem[];
}

export interface Tenant {
  id: string;
  name: string;
  status: 'active' | 'suspended' | string;
  createdAt?: string;
}

/** A dashboard user (admin API `/admin/users`). The password hash is never sent. */
export interface DashboardUser {
  id: string;
  userName: string;
  role: Role;
  /** Absent for administrators. */
  tenantId?: string | null;
  enabled: boolean;
  createdAt: string;
  /** Present only in the create and reset responses, and only when the server generated the password. */
  password?: string;
}

export interface CreateUserRequest {
  userName: string;
  role: Role;
  tenantId?: string;
  /** Omit it to let the server generate one (shown once). */
  password?: string;
}

export interface CertificateInfo {
  id: string;
  subject: string;
  issuer?: string;
  san: string[];
  notBefore?: string;
  notAfter: string;
  source: 'acme' | 'upload' | 'self_signed' | string;
  active: boolean;
  thumbprint?: string;
}

export interface PressureIndicators {
  writerQueueDepth: number;
  writerQueueOverThresholdSeconds: number;
  commitP99Ms: number;
  /** True when the advisory thresholds (queue over 1,000 for 5 min, p99 over about 100 ms) are exceeded. */
  advisory: boolean;
}

/** Renewal state of a certificate requested through ACME (GET /admin/certificates/acme). */
export interface AcmeRenewal {
  certificateName: string;
  status: string;
  lastAttemptAt?: string | null;
  nextAttemptAt?: string | null;
  failures?: number;
  lastError?: string | null;
}

/** GET /admin/maintenance: the background storage maintenance. */
export interface MaintenanceState {
  running: boolean;
  startedAt?: string | null;
  finishedAt?: string | null;
  error?: string | null;
  reports: { job: string; durationMs: number; rowsAffected: number; detail?: string | null }[];
}

export interface AdminStatus {
  version: string;
  backend: string;
  historyMode: HistoryMode;
  uptimeSeconds?: number;
  queue: { depth: number; deferred: number; oldestDueAt?: string | null };
  storage: { healthy: boolean; detail?: string; warnings: CapabilityWarning[] };
  certificates: { subject: string; notAfter: string; source: string }[];
  pressure?: PressureIndicators;
  switch: { state: SwitchState };
}

// ---- storage switch ----

export type SwitchState =
  | 'none'
  | 'draining'
  | 'quiescing'
  | 'fenced'
  | 'exporting'
  | 'importing'
  | 'verifying'
  | 'verified'
  | 'confirmed'
  | 'active'
  | 'finalized'
  | 'rolled_back'
  | 'failed';

export type SwitchTarget = 'postgres' | 'sqlite';
export type SwitchMode = 'drain' | 'quiesce';
export type SwitchInclude = 'queue' | 'history';

export interface SwitchTargetConfig {
  /** PostgreSQL connection string reference or host fields; secrets are referenced by name. */
  connectionName?: string;
  host?: string;
  port?: number;
  database?: string;
  /** SQLite data directory. */
  path?: string;
}

export interface SwitchRequest {
  to: SwitchTarget;
  target: SwitchTargetConfig;
  include: SwitchInclude[];
  mode: SwitchMode;
}

export interface SwitchStartRequest extends SwitchRequest {
  exportPassphrase: string;
  /** Echo of the typed confirmation phrase. */
  confirmation: string;
}

export interface PreflightCheck {
  name: string;
  ok: boolean;
  message: string;
  severity?: 'info' | 'warning' | 'error';
}

export interface PreflightReport {
  ok: boolean;
  checks: PreflightCheck[];
  counts: { queuedMessages: number; historyRows: number; historyBytes: number; statsRows: number };
  estimate?: { seconds?: number; bytes?: number; unverified?: boolean };
  /** Statements about what will not carry over (for example history when the target is statsonly). */
  notCarried: string[];
  orchestratorManaged: boolean;
}

export interface VerifyTableCount {
  table: string;
  expected: number;
  actual: number;
}

export interface VerifyReport {
  ok: boolean;
  tables: VerifyTableCount[];
  checksumsOk: boolean;
  checkedAt?: string;
}

export interface SwitchStatus {
  switchId?: string;
  state: SwitchState;
  direction?: { from: string; to: string };
  mode?: SwitchMode;
  include?: SwitchInclude[];
  progress?: { phase: string; percent: number; rowsDone?: number; rowsTotal?: number };
  verifyReport?: VerifyReport;
  /** Present when the deployment is orchestrator-managed and the state is confirmed. */
  cutoverPatch?: { kind: string; text: string } | null;
  orchestratorManaged?: boolean;
  startedAt?: string;
  updatedAt?: string;
  error?: string | null;
}

// ---- relay routes and TLS policies (admin; docs/api.md "Relay routes and TLS policies") ----

export type RelayTlsMode = 'none' | 'starttls' | 'required' | 'verify' | 'implicit';

export interface RelayRoute {
  id: string;
  name: string;
  host: string;
  port: number;
  tlsMode: RelayTlsMode;
  userName: string | null;
  /** Whether a password is stored. The password itself is never returned. */
  hasPassword: boolean;
  priority: number;
  enabled: boolean;
  domains: string[];
  warnings: string[];
}

/** Create body. `password` is write-only. */
export interface RelayRouteCreate {
  name: string;
  host: string;
  port?: number;
  tlsMode?: RelayTlsMode;
  userName?: string;
  password?: string;
  priority?: number;
  enabled?: boolean;
  domains: string[];
}

/** Patch body: every member is optional; `password` is write-only and `removeCredentials` clears the user name and password. */
export interface RelayRoutePatch {
  name?: string;
  host?: string;
  port?: number;
  tlsMode?: RelayTlsMode;
  userName?: string;
  password?: string;
  removeCredentials?: boolean;
  priority?: number;
  enabled?: boolean;
  domains?: string[];
}

export type TlsPolicyLevel = 'none' | 'may' | 'encrypt' | 'verify';

export interface TlsPolicy {
  id: string;
  domainPattern: string;
  level: TlsPolicyLevel;
  warnings: string[];
}

export interface TlsPolicyCreate {
  domainPattern: string;
  level: TlsPolicyLevel;
  /** Required by the server to save level none for the pattern "*". */
  acknowledgeInsecure?: boolean;
}

export interface TlsPolicyPatch {
  domainPattern?: string;
  level?: TlsPolicyLevel;
  /** Required by the server when the update makes the policy level none for "*". */
  acknowledgeInsecure?: boolean;
}
