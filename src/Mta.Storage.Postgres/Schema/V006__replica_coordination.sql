-- Version 6: what replicas on one database exchange about each other and about remote destinations. Frozen like V001: never edit, add the next version.
--
-- These tables are deliberately not part of the EF model, the backend switch bundle or the SQLite schema: the state is ephemeral (rebuilt by the running replicas
-- within seconds), only meaningful with more than one process, and SQLite is one process by design. All times in them are the database server's clock.
--
--  * replica_heartbeat: who is alive, so per-destination limits are shared out among the live replicas.
--  * replica_signal: what a replica learned about a remote destination (a circuit opened, a throttling reply) for the others to act on.
--  * auth_failure: failed-login counts per keyed digest of an address or user name and time bucket, so the lockout budget is shared by all replicas.

CREATE TABLE replica_heartbeat (
    replica_name text COLLATE "C" NOT NULL,
    beat_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_replica_heartbeat" PRIMARY KEY (replica_name)
);

CREATE TABLE replica_signal (
    signal_kind smallint NOT NULL,
    signal_key text COLLATE "C" NOT NULL,
    replica_name text COLLATE "C" NOT NULL,
    raised_at timestamp with time zone NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    cooldown_ms bigint NOT NULL,
    CONSTRAINT "PK_replica_signal" PRIMARY KEY (signal_kind, signal_key, replica_name)
);

CREATE INDEX "IX_replica_signal_valid_until" ON replica_signal (valid_until);

CREATE TABLE auth_failure (
    key_digest text COLLATE "C" NOT NULL,
    bucket_index bigint NOT NULL,
    failure_count bigint NOT NULL,
    CONSTRAINT "PK_auth_failure" PRIMARY KEY (key_digest, bucket_index)
);

CREATE INDEX "IX_auth_failure_bucket_index" ON auth_failure (bucket_index);
