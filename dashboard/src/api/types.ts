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
  /** Whether the server receives mail (`Inbound:Enabled`): the inbound pages are shown only then. */
  inbound: { enabled: boolean };
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
export type RecordPurpose = 'dkim' | 'return_path' | 'spf' | 'dmarc' | 'bounce_mx' | 'tls_rpt' | 'mta_sts' | 'mta_sts_host' | 'ptr' | 'inbound_mx';
/**
 * `missing`: nothing of that kind at the name. `invalid`: a record exists but is malformed or there are several where one is allowed.
 * `mismatch`: a well-formed record exists with another value than expected. `pending`: not looked up yet.
 */
export type RecordStatus = 'ok' | 'missing' | 'invalid' | 'mismatch' | 'pending';

export interface DnsRecord {
  type: string;
  host: string;
  value: string;
  ttl: number;
  purpose: RecordPurpose;
  status: RecordStatus;
  found?: string | null;
  expected?: string;
  /** Required records decide whether the domain can send; the others are recommended. */
  required: boolean;
  /** False for advice the customer cannot act on in the domain's zone (the reverse DNS of the sending IP, the operator's bounce MX): it does not count in "published" totals. */
  publishable: boolean;
  /** One sentence saying what the record is for. */
  note?: string | null;
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
  /** Verified (or in the grace period of a temporary failure) and not paused: mail can be sent from the domain. */
  readyToSend: boolean;
  records: DnsRecord[];
  /** The newest key (which may be a pending rotation). */
  dkim: DkimKeyInfo;
  /** Every key, oldest first. Absent in older servers and fixtures. */
  dkimKeys?: DkimKeyInfo[];
}

/** The MTA-STS policy file EggMail serves for a domain. */
export interface MtaStsPolicy {
  url: string;
  host: string;
  content: string;
}

/** `GET /domains/{id}/records`: what to publish, as records and as zone-file text. Nothing is looked up in DNS by this call. */
export interface DomainRecords {
  id: string;
  name: string;
  readyToSend: boolean;
  checkedAt: string | null;
  records: DnsRecord[];
  zoneFile: string;
  mtaStsPolicy: MtaStsPolicy | null;
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

export const API_KEY_SCOPES = ['send', 'read', 'domains', 'webhooks', 'suppressions', 'keys', 'inbound:read', 'inbound:write'] as const;

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

/**
 * Advisory storage-pressure figures (GET /admin/status). SQLite sends the writer fields (decision 108),
 * PostgreSQL the pool fields (decision 109); the other backend's fields are absent.
 */
export interface PressureIndicators {
  writerQueueDepth?: number;
  writerQueueOverThresholdSeconds?: number;
  commitP99Ms?: number;
  /** True when the backend's advisory thresholds are exceeded. */
  advisory: boolean;
  /** The configured thresholds (`Sqlite:Pressure*`); absent from an older server, which used the defaults. */
  queueDepthThreshold?: number;
  queueThresholdSeconds?: number;
  commitP99ThresholdMs?: number;
  /** PostgreSQL: callers waiting for a pooled connection right now. */
  poolPendingRequests?: number;
  poolConnectionsInUse?: number;
  poolMaxSize?: number;
  /** PostgreSQL: share of the samples in the window that found a caller waiting, 0 to 100. */
  poolWaitingPercent?: number;
  poolSamples?: number;
  /** PostgreSQL: connection requests that timed out in the window. */
  poolTimeouts?: number;
  poolWindowSeconds?: number;
  /** PostgreSQL: the configured `Storage:Postgres:PressureWaitingPercent`. */
  poolWaitingPercentThreshold?: number;
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


// ---- inbound mail (docs/api.md, "Inbound mail", design section 11) ----

export type InboundVerdictWord = 'none' | 'pass' | 'fail' | 'softfail' | 'neutral' | 'temperror' | 'permerror' | 'policy';
export type DmarcActionWord = 'record_only' | 'flag' | 'reject';
export type InboundActionKindWord = 'webhook' | 'forward' | 'store' | 'discard';
export type InboundActionStateWord = 'pending' | 'done' | 'failed';
export type InboundMatchKindWord = 'catch_all' | 'address' | 'wildcard';
export type InboundWebhookFormatWord = 'json' | 'raw_mime';

export interface InboundWarning {
  code: string;
  message: string;
}

/** The limits that apply to a domain after the operator's ceilings (0 means unlimited for `maxStoredBytes`, forever for `retentionDays`). */
export interface InboundEffective {
  maxMessageBytes: number;
  maxMessagesPerMinute: number;
  maxMessagesPerMinutePerRemote: number;
  maxStoredBytes: number;
  retentionDays: number;
}

export interface InboundSettings {
  domainId: string;
  enabled: boolean;
  dmarcAction: DmarcActionWord;
  /** null means the server value (see `effective`). */
  maxMessageBytes: number | null;
  maxMessagesPerMinute: number | null;
  maxMessagesPerMinutePerRemote: number | null;
  maxStoredBytes: number | null;
  retentionDays: number | null;
  updatedAt: string | null;
  effective: InboundEffective;
  mx: { host: string | null; priority: number; status?: RecordStatus };
  warnings?: InboundWarning[];
}

/** PATCH body: absent members are unchanged, null resets a limit to the server value. */
export interface InboundSettingsPatch {
  enabled?: boolean;
  dmarcAction?: DmarcActionWord;
  maxMessageBytes?: number | null;
  maxMessagesPerMinute?: number | null;
  maxMessagesPerMinutePerRemote?: number | null;
  maxStoredBytes?: number | null;
  retentionDays?: number | null;
}

export interface InboundRouteMatch {
  kind: InboundMatchKindWord;
  localPart?: string | null;
  plusAddressing?: boolean;
}

export interface InboundRouteAction {
  kind: InboundActionKindWord;
  webhookEndpointId?: string | null;
  webhookFormat?: InboundWebhookFormatWord | null;
  forwardTo?: string[];
}

export interface InboundRoute {
  id: string;
  domainId: string;
  name: string;
  order: number;
  enabled: boolean;
  match: InboundRouteMatch;
  action: InboundRouteAction;
  createdAt: string;
  updatedAt: string;
  warnings?: InboundWarning[];
}

export interface InboundRouteInput {
  name?: string;
  order?: number;
  enabled?: boolean;
  match?: InboundRouteMatch;
  action?: InboundRouteAction;
}

/** What the receive path would answer for a recipient (`GET /domains/{id}/inbound/routes/match`). */
export interface InboundRouteProbe {
  address: string;
  domainEnabled: boolean;
  route: InboundRoute | null;
  reply: string;
}

export interface InboundVerdict {
  result: InboundVerdictWord;
  domain?: string | null;
  policy?: string | null;
}

export interface InboundAuth {
  spf: InboundVerdict;
  spfHelo: InboundVerdict;
  dkim: InboundVerdict;
  dmarc: InboundVerdict;
  arc: InboundVerdict;
}

export interface InboundAction {
  /** The action the message was given when it was received; the action that runs is its route's current one (`currentKind`, detail only). */
  kind: InboundActionKindWord;
  state: InboundActionStateWord;
  attempts: number;
  retryGeneration: number;
  nextAttemptAt: string | null;
  finishedAt: string | null;
  lastError: string | null;
  forwardMessageId: string | null;
  note?: string | null;
  currentKind?: InboundActionKindWord | null;
}

export interface InboundMessageSummary {
  id: string;
  domainId: string;
  domain: string;
  receivedAt: string;
  remoteIp: string;
  helo: string | null;
  tls: boolean;
  from: string;
  to: string;
  subject: string | null;
  size: number;
  auth: InboundAuth;
  dmarcFlagged: boolean;
  routeId: string | null;
  action: InboundAction;
  hasRaw: boolean;
}

export interface InboundAttachment {
  index: number;
  filename: string | null;
  content_type: string;
  size: number;
  content_id: string | null;
  disposition: string;
}

export interface InboundContent {
  state: 'available' | 'no_body';
  headers: { name: string; value: string }[];
  text?: string | null;
  html?: string | null;
  truncated: boolean;
  attachments: InboundAttachment[];
}

export interface InboundMessageDetail extends InboundMessageSummary {
  content: InboundContent;
}

export interface InboundMessageQuery {
  domainId?: string;
  recipient?: string;
  sender?: string;
  subject?: string;
  route?: string;
  action?: InboundActionKindWord;
  state?: InboundActionStateWord;
  dmarc?: InboundVerdictWord;
  dmarcFlagged?: boolean;
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string;
}

export interface InboundUsage {
  messages: number;
  bodyBytes: number;
  pending: number;
  failed: number;
  oldestPendingAt: string | null;
}
