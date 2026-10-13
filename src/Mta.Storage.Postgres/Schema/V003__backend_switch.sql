-- Version 3: the backend switch (design 4.6). A hold column on queued rows (a transfer mark on the source, an activation hold
-- on the target; a held row is never claimed) and one progress table per model part. Frozen like V001: never edit, add V004.

ALTER TABLE delivery_queue ADD COLUMN transfer_switch_id uuid;
ALTER TABLE webhook_outbox ADD COLUMN transfer_switch_id uuid;

CREATE TABLE transfer_chunk_config (
    switch_id uuid NOT NULL,
    chunk_id text COLLATE "C" NOT NULL,
    table_name text COLLATE "C" NOT NULL,
    rows bigint NOT NULL,
    checksum text COLLATE "C" NOT NULL,
    applied_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_transfer_chunk_config" PRIMARY KEY (switch_id, chunk_id)
);

CREATE TABLE transfer_chunk_queue (
    switch_id uuid NOT NULL,
    chunk_id text COLLATE "C" NOT NULL,
    table_name text COLLATE "C" NOT NULL,
    rows bigint NOT NULL,
    checksum text COLLATE "C" NOT NULL,
    applied_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_transfer_chunk_queue" PRIMARY KEY (switch_id, chunk_id)
);

CREATE TABLE transfer_chunk_stats (
    switch_id uuid NOT NULL,
    chunk_id text COLLATE "C" NOT NULL,
    table_name text COLLATE "C" NOT NULL,
    rows bigint NOT NULL,
    checksum text COLLATE "C" NOT NULL,
    applied_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_transfer_chunk_stats" PRIMARY KEY (switch_id, chunk_id)
);

CREATE TABLE transfer_chunk_history (
    switch_id uuid NOT NULL,
    chunk_id text COLLATE "C" NOT NULL,
    table_name text COLLATE "C" NOT NULL,
    rows bigint NOT NULL,
    checksum text COLLATE "C" NOT NULL,
    applied_at timestamp with time zone NOT NULL,
    CONSTRAINT "PK_transfer_chunk_history" PRIMARY KEY (switch_id, chunk_id)
);
