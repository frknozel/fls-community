CREATE TABLE IF NOT EXISTS archive_tls_alert_history (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 destination_id INT UNSIGNED NOT NULL,
 destination_name VARCHAR(100) NOT NULL,
 host VARCHAR(253) NOT NULL,
 port SMALLINT UNSIGNED NOT NULL,
 destination_revision INT UNSIGNED NOT NULL,
 alert_code VARCHAR(64) NOT NULL,
 severity VARCHAR(8) NOT NULL,
 message VARCHAR(600) NOT NULL,
 condition_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 warning_days SMALLINT UNSIGNED NOT NULL,
 critical_days SMALLINT UNSIGNED NOT NULL,
 settings_revision INT UNSIGNED NOT NULL,
 certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 expires_at DATETIME(6) NULL,
 days_remaining_at_start INT NULL,
 triggered_at DATETIME(6) NOT NULL,
 last_seen_at DATETIME(6) NOT NULL,
 closed_at DATETIME(6) NULL,
 closure_reason VARCHAR(32) NOT NULL DEFAULT '',
 is_open TINYINT AS (IF(closed_at IS NULL,1,NULL)) VIRTUAL,
 UNIQUE KEY tls_one_open(destination_id,alert_code,is_open),
 KEY tls_history_time(triggered_at,id),
 KEY tls_history_target(destination_id,triggered_at,id),
 KEY tls_history_open(closed_at,triggered_at,id),
 CONSTRAINT tls_history_severity CHECK(severity IN ('warning','error')),
 CONSTRAINT tls_history_thresholds CHECK(warning_days BETWEEN 1 AND 3650 AND critical_days BETWEEN 1 AND warning_days)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS archive_tls_history_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 coverage_from_at DATETIME(6) NULL,
 checked_at DATETIME(6) NULL,
 worker_checked_at DATETIME(6) NULL,
 CONSTRAINT tls_history_singleton CHECK(id=1)
) ENGINE=InnoDB;
INSERT IGNORE INTO archive_tls_history_state(id) VALUES(1);
