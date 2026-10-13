-- Version 4: delivery_queue.smtp_utf8, true when the message's header section is internationalized (RFC 6532), so sending it
-- needs the SMTPUTF8 extension. Existing rows get false (delivery re-checks the headers of the stored message anyway).
-- Frozen like V001: never edit, add the next version.

ALTER TABLE delivery_queue ADD COLUMN smtp_utf8 boolean NOT NULL DEFAULT false;
