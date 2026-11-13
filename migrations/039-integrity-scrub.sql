CREATE TABLE IF NOT EXISTS archive_integrity_checks (
 manifest_id INT UNSIGNED PRIMARY KEY,
 last_full_verified_at DATETIME(6) NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'pending',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 progress_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
 verification_started_at DATETIME(6) NULL,
 updated_at DATETIME(6) NOT NULL,
 KEY oldest_full_check(last_full_verified_at,manifest_id),
 KEY check_status(status,manifest_id),
 CONSTRAINT integrity_check_manifest FOREIGN KEY(manifest_id) REFERENCES archive_manifests(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS archive_integrity_worker (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 status VARCHAR(16) NOT NULL DEFAULT 'idle',
 last_started_at DATETIME(6) NULL,
 last_finished_at DATETIME(6) NULL,
 heartbeat_at DATETIME(6) NULL,
 bytes_read BIGINT UNSIGNED NOT NULL DEFAULT 0,
 files_verified INT UNSIGNED NOT NULL DEFAULT 0,
 current_manifest_id INT UNSIGNED NULL,
 max_bytes BIGINT UNSIGNED NOT NULL DEFAULT 536870912,
 max_seconds INT UNSIGNED NOT NULL DEFAULT 45,
 read_bytes_per_second BIGINT UNSIGNED NOT NULL DEFAULT 8388608,
 target_age_days INT UNSIGNED NOT NULL DEFAULT 30,
 last_error_code VARCHAR(64) NOT NULL DEFAULT ''
) ENGINE=InnoDB;
INSERT IGNORE INTO archive_integrity_checks(manifest_id,last_full_verified_at,status,error_code,progress_bytes,updated_at)
 SELECT id,IF(status='verified',verified_at,NULL),
 CASE WHEN status='FAILED' THEN 'FAILED' WHEN status='verified' AND verified_at IS NOT NULL THEN 'verified' ELSE 'pending' END,
 IF(status='FAILED','legacy_integrity_failure',''),0,UTC_TIMESTAMP(6) FROM archive_manifests;
INSERT IGNORE INTO archive_integrity_worker(id) VALUES(1);
