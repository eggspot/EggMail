-- Version 9: the index the per-tenant claim of the inbound route actions probes. The claim takes the oldest due rows of each tenant that has pending actions
-- (one index probe per tenant), so a very large backlog of one tenant is not read and sorted to find the rows of the others. Partial, like the index on
-- action_next_attempt_at: only pending rows are in it. Building it blocks writes to inbound_message while it runs; see docs/operations.md (Upgrades).
-- Frozen like V001: never edit, add the next version.

CREATE INDEX IF NOT EXISTS "IX_inbound_message_tenant_id_action_next_attempt_at_id" ON inbound_message (tenant_id, action_next_attempt_at, id) WHERE action_state = 0;
