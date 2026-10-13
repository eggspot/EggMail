-- EggMail PostgreSQL schema, version 2 (frozen once released: add V003 instead).
--
-- The HTTP API: dashboard users and server-side sessions (config part of the shared model), and the request fingerprint stored
-- with an idempotency key so a key reused with another body is detected. Same conventions as version 1.

CREATE TABLE dashboard_user (
    id uuid NOT NULL,
    user_name text COLLATE "C" NOT NULL,
    password_hash text COLLATE "C" NOT NULL,
    role smallint NOT NULL,
    tenant_id uuid,
    enabled boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_dashboard_user" PRIMARY KEY (id)
);

CREATE UNIQUE INDEX "IX_dashboard_user_user_name" ON dashboard_user (user_name);

CREATE TABLE dashboard_session (
    id_hash bytea NOT NULL,
    user_id uuid NOT NULL,
    csrf_token text COLLATE "C" NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_dashboard_session" PRIMARY KEY (id_hash)
);

CREATE INDEX "IX_dashboard_session_user_id" ON dashboard_session (user_id);

CREATE INDEX "IX_dashboard_session_expires_at" ON dashboard_session (expires_at);

ALTER TABLE api_idempotency_key ADD COLUMN fingerprint text COLLATE "C";
