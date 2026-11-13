CREATE TABLE IF NOT EXISTS archive_tls_settings (
 id TINYINT UNSIGNED PRIMARY KEY,
 warning_days SMALLINT UNSIGNED NOT NULL DEFAULT 30,
 critical_days SMALLINT UNSIGNED NOT NULL DEFAULT 7,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_by VARCHAR(64) NOT NULL DEFAULT 'system',
 CONSTRAINT archive_tls_settings_singleton CHECK(id=1),
 CONSTRAINT archive_tls_settings_thresholds CHECK(warning_days BETWEEN 1 AND 3650 AND critical_days BETWEEN 1 AND warning_days)
) ENGINE=InnoDB;
INSERT IGNORE INTO archive_tls_settings(id) VALUES(1);
