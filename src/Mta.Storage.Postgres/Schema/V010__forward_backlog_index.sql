-- Version 10: the index the forward action counts through. Before it queues a copy of received mail, the forward action counts the forwards its tenant (and the route's domain) still have waiting
-- in the outbound queue and refuses to add more past the operator's caps (Inbound:Forward:*). Partial: only rows of source Forward (MessageSource.Forward = 4) are in it, so it costs the rest of
-- the queue nothing. Building it blocks writes to delivery_queue while it runs; see docs/operations.md (Upgrades). Frozen like V001: never edit, add the next version.

CREATE INDEX IF NOT EXISTS "IX_delivery_queue_tenant_id_sending_domain" ON delivery_queue (tenant_id, sending_domain) WHERE source = 4;
