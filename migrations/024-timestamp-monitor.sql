ALTER TABLE timestamp_settings
 ADD COLUMN IF NOT EXISTS signing_mode VARCHAR(16) NOT NULL DEFAULT 'provider',
 ADD COLUMN IF NOT EXISTS allow_local_fallback TINYINT NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS local_accepted_at DATETIME(6) NULL,
 ADD COLUMN IF NOT EXISTS local_accepted_by VARCHAR(64) NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS local_acceptance_version INT UNSIGNED NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS low_credit_threshold INT UNSIGNED NOT NULL DEFAULT 100,
 ADD COLUMN IF NOT EXISTS stall_minutes INT UNSIGNED NOT NULL DEFAULT 15,
 ADD COLUMN IF NOT EXISTS scope_started_at DATETIME(6) NULL;
UPDATE timestamp_settings SET scope_started_at=updated_at WHERE start_manifest_id>0 AND scope_started_at IS NULL;
ALTER TABLE timestamp_profiles
 ADD COLUMN IF NOT EXISTS balance_attempted_at DATETIME(6) NULL,
 ADD COLUMN IF NOT EXISTS balance_basis_attempt_id BIGINT UNSIGNED NOT NULL DEFAULT 0;
UPDATE timestamp_profiles SET balance_attempted_at=balance_at WHERE balance_attempted_at IS NULL;
ALTER TABLE timestamp_stamps ADD COLUMN IF NOT EXISTS created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6);
