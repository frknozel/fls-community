-- Product retention policy. No deletion job or remote rotation is enabled here.
CREATE TABLE IF NOT EXISTS retention_settings (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 retention_years TINYINT UNSIGNED NOT NULL,
 fast_days SMALLINT UNSIGNED NOT NULL,
 revision BIGINT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 updated_by VARCHAR(64) NOT NULL,
 CONSTRAINT retention_singleton CHECK (id=1),
 CONSTRAINT retention_years_range CHECK (retention_years BETWEEN 2 AND 5),
 CONSTRAINT retention_fast_days_range CHECK (fast_days BETWEEN 90 AND 180),
 CONSTRAINT retention_revision_positive CHECK (revision>=1)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS retention_policy_versions (
 revision BIGINT UNSIGNED NOT NULL PRIMARY KEY,
 retention_years TINYINT UNSIGNED NOT NULL,
 fast_days SMALLINT UNSIGNED NOT NULL,
 effective_at DATETIME(6) NOT NULL,
 recorded_at DATETIME(6) NOT NULL,
 recorded_by VARCHAR(64) NOT NULL,
 KEY retention_effective (effective_at,revision),
 CONSTRAINT retention_history_years_range CHECK (retention_years BETWEEN 2 AND 5),
 CONSTRAINT retention_history_fast_range CHECK (fast_days BETWEEN 90 AND 180)
) ENGINE=InnoDB;
INSERT IGNORE INTO retention_settings(id,retention_years,fast_days,revision,updated_at,updated_by)
VALUES(1,2,120,1,UTC_TIMESTAMP(6),'system');
-- The initial minimum also protects records received before this migration.
INSERT IGNORE INTO retention_policy_versions(revision,retention_years,fast_days,effective_at,recorded_at,recorded_by)
VALUES(1,2,120,'1970-01-01 00:00:00.000000',UTC_TIMESTAMP(6),'system');
