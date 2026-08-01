ALTER TABLE scheduled_executions
    ADD COLUMN recovery_protocol_version SMALLINT NOT NULL DEFAULT 0
    CHECK (recovery_protocol_version >= 0);
