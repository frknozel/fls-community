CREATE TABLE IF NOT EXISTS summary_backlog_incidents (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 incident_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
 started_at DATETIME(6) NOT NULL,
 triggered_at DATETIME(6) NOT NULL,
 minimum_pending INT UNSIGNED NOT NULL,
 minimum_seconds INT UNSIGNED NOT NULL,
 settings_revision BIGINT UNSIGNED NULL,
 peak_pending BIGINT UNSIGNED NOT NULL,
 last_pending BIGINT UNSIGNED NOT NULL,
 last_confirmed_at DATETIME(6) NOT NULL,
 last_sample_at DATETIME(6) NOT NULL,
 status VARCHAR(24) NOT NULL,
 resolved_at DATETIME(6) NULL,
 drained_at DATETIME(6) NULL,
 had_measurement_gap TINYINT UNSIGNED NOT NULL DEFAULT 0,
 KEY backlog_trigger(triggered_at,id),
 KEY backlog_resolution(resolved_at,triggered_at),
 CONSTRAINT backlog_incident_status CHECK (status IN ('active','drained','rule_changed','unconfirmed'))
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS summary_backlog_history_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 cursor_file VARCHAR(80) NOT NULL DEFAULT '',
 cursor_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
 cursor_inode BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_sample_at DATETIME(6) NULL,
 coverage_from_at DATETIME(6) NULL,
 open_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 gap_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
 ready TINYINT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NULL
) ENGINE=InnoDB;
INSERT IGNORE INTO summary_backlog_history_state(id) VALUES(1);
