-- Version 4: state the process used to keep in memory only, and what an asynchronous bounce needs to find its message. Frozen like V001: never edit, add V005.
--
--  * domain_record_check: the last DNS check result of each record of a domain (domain verification), so a restart or another replica shows the real state.
--  * tls_rpt_bucket: an append-only journal of TLS-RPT collector flushes per policy domain and UTC day; the report sender merges and deletes them.
--  * sending_counter: the hourly and daily sending counters behind the caps and the warm-up; replicas add their deltas, the value is the sum.
--  * message_index.message_id_header (normalized Message-ID, indexed per tenant) and message_index.tags (JSON array): the history of a message can be found
--    from a returned bounce, and carries the API caller's tags. Added to the partitioned parent, so existing and future partitions get them.

CREATE TABLE domain_record_check (
    domain_id uuid NOT NULL,
    record_key text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    found text COLLATE "C",
    checked_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_domain_record_check" PRIMARY KEY (domain_id, record_key)
);

CREATE TABLE tls_rpt_bucket (
    id uuid NOT NULL,
    day integer NOT NULL,
    policy_domain text COLLATE "C" NOT NULL,
    data_json text COLLATE "C" NOT NULL,
    attempts integer NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_tls_rpt_bucket" PRIMARY KEY (id)
);

CREATE INDEX "IX_tls_rpt_bucket_day_policy_domain" ON tls_rpt_bucket (day, policy_domain);

CREATE TABLE sending_counter (
    scope smallint NOT NULL,
    tenant_id uuid NOT NULL,
    domain text COLLATE "C" NOT NULL,
    window_kind smallint NOT NULL,
    window_index bigint NOT NULL,
    count bigint NOT NULL,
    CONSTRAINT "PK_sending_counter" PRIMARY KEY (scope, tenant_id, domain, window_kind, window_index)
);

ALTER TABLE message_index ADD COLUMN message_id_header text COLLATE "C";

ALTER TABLE message_index ADD COLUMN tags text COLLATE "C";

CREATE INDEX "IX_message_index_tenant_id_message_id_header" ON message_index (tenant_id, message_id_header);
