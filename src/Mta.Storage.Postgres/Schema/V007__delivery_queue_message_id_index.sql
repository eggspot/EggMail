-- Version 7: an index on delivery_queue (message_id), so cancelling a message (and any other lookup of one message's waiting deliveries) finds its rows without
-- scanning the whole queue. Building it takes a lock that blocks writes to delivery_queue for the duration, which is short for a queue of a few hundred
-- thousand rows; see docs/operations.md (Upgrades). Frozen like V001: never edit, add the next version.

CREATE INDEX IF NOT EXISTS "IX_delivery_queue_message_id" ON delivery_queue (message_id);
