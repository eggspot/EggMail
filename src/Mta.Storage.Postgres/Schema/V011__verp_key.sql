-- Version 11: the VERP signing keys (decision 107), protected with Data Protection instead of plain JSON in the setting bounce.verp.keys, which the first start of this version
-- moves into this table. key_id is the 4-bit key id a bounce address carries (0 to 15). Frozen like V001: never edit, add the next version.

CREATE TABLE IF NOT EXISTS verp_key (
    key_id integer NOT NULL,
    key_protected bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    activates_at timestamp with time zone NOT NULL,
    retired_at timestamp with time zone,
    CONSTRAINT "PK_verp_key" PRIMARY KEY (key_id)
);
