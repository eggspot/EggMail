-- Version 8: inbound mail (decision 95). Frozen like V001: never edit, add the next version.
--
--  * inbound_domain_settings, inbound_route: the per-domain inbound switch and settings, and the routes (config part). Deleted with the domain by the application.
--  * inbound_message, inbound_message_raw: received mail, one row and one body per accepted recipient, with the verification results and the state of the route
--    action (queue part). Not partitioned: retention differs per domain (and can be unlimited), so it is a batched delete, as on SQLite.

CREATE TABLE inbound_domain_settings (
    domain_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    enabled boolean NOT NULL,
    dmarc_action smallint NOT NULL,
    max_message_bytes bigint,
    max_messages_per_minute integer,
    max_messages_per_minute_per_remote integer,
    max_stored_bytes bigint,
    retention_days integer,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_inbound_domain_settings" PRIMARY KEY (domain_id)
);

CREATE INDEX "IX_inbound_domain_settings_tenant_id" ON inbound_domain_settings (tenant_id);

CREATE INDEX "IX_inbound_domain_settings_enabled" ON inbound_domain_settings (enabled);

CREATE TABLE inbound_route (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    name text COLLATE "C" NOT NULL,
    sort_order integer NOT NULL,
    enabled boolean NOT NULL,
    match_kind smallint NOT NULL,
    local_part text COLLATE "C",
    plus_addressing boolean NOT NULL,
    action_kind smallint NOT NULL,
    webhook_endpoint_id uuid,
    webhook_format smallint NOT NULL,
    forward_to_json text COLLATE "C" NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_inbound_route" PRIMARY KEY (id)
);

CREATE INDEX "IX_inbound_route_domain_id_sort_order_id" ON inbound_route (domain_id, sort_order, id);

CREATE INDEX "IX_inbound_route_tenant_id" ON inbound_route (tenant_id);

CREATE INDEX "IX_inbound_route_webhook_endpoint_id" ON inbound_route (webhook_endpoint_id);

CREATE TABLE inbound_message (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    domain text COLLATE "C" NOT NULL,
    received_at timestamp with time zone NOT NULL,
    remote_address text COLLATE "C" NOT NULL,
    helo text COLLATE "C",
    tls_used boolean NOT NULL,
    envelope_from text COLLATE "C" NOT NULL,
    envelope_to text COLLATE "C" NOT NULL,
    subject text COLLATE "C",
    size bigint NOT NULL,
    spf smallint NOT NULL,
    spf_domain text COLLATE "C",
    spf_helo smallint NOT NULL,
    dkim smallint NOT NULL,
    dkim_domain text COLLATE "C",
    dmarc smallint NOT NULL,
    dmarc_policy text COLLATE "C",
    arc smallint NOT NULL,
    disposition smallint NOT NULL,
    route_id uuid,
    action_kind smallint NOT NULL,
    action_state smallint NOT NULL,
    action_attempts integer NOT NULL,
    retry_generation integer NOT NULL,
    action_next_attempt_at timestamp with time zone,
    action_finished_at timestamp with time zone,
    action_last_error text COLLATE "C",
    action_note text COLLATE "C",
    forward_message_id uuid,
    has_raw boolean NOT NULL,
    lease_owner text COLLATE "C",
    claim_sequence bigint NOT NULL,
    lease_until timestamp with time zone NOT NULL,
    transfer_switch_id uuid,
    CONSTRAINT "PK_inbound_message" PRIMARY KEY (id)
)
WITH (fillfactor = 85, autovacuum_vacuum_scale_factor = 0.05);

CREATE INDEX "IX_inbound_message_tenant_id_id" ON inbound_message (tenant_id, id);

CREATE INDEX "IX_inbound_message_tenant_id_envelope_to_id" ON inbound_message (tenant_id, envelope_to, id);

CREATE INDEX "IX_inbound_message_domain_id_received_at" ON inbound_message (domain_id, received_at);

CREATE INDEX "IX_inbound_message_domain_id_id" ON inbound_message (domain_id, id);

CREATE INDEX "IX_inbound_message_action_next_attempt_at" ON inbound_message (action_next_attempt_at) WHERE action_state = 0;

CREATE INDEX "IX_inbound_message_received_at" ON inbound_message (received_at) WHERE action_state <> 0;

CREATE TABLE inbound_message_raw (
    message_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    raw bytea NOT NULL,
    CONSTRAINT "PK_inbound_message_raw" PRIMARY KEY (message_id)
);
