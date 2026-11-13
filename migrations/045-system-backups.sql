-- Manual system backups: PHP writes settings and queue intent only.
CREATE TABLE IF NOT EXISTS system_backup_settings (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 destination_id INT UNSIGNED NULL,
 db_dump_directory VARCHAR(400) NOT NULL DEFAULT 'DB-Dump',
 system_backup_directory VARCHAR(400) NOT NULL DEFAULT 'FLS-Backups',
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_by VARCHAR(64) NOT NULL DEFAULT 'system',
 CONSTRAINT system_backup_settings_singleton CHECK(id=1),
 CONSTRAINT system_backup_settings_revision CHECK(revision>=1),
 CONSTRAINT system_backup_settings_destination FOREIGN KEY(destination_id) REFERENCES archive_destinations(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backups (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 filename VARCHAR(100) NOT NULL,
 bytes BIGINT UNSIGNED NOT NULL,
 sha256 CHAR(64) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'ready',
 created_at DATETIME(6) NOT NULL,
 verified_at DATETIME(6) NOT NULL,
 created_by VARCHAR(64) NOT NULL DEFAULT '',
 created_job_id BIGINT UNSIGNED NULL,
 UNIQUE KEY system_backup_filename(filename),
 CONSTRAINT system_backup_status CHECK(status IN ('ready','missing'))
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_jobs (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 request_key CHAR(36) NOT NULL,
 action VARCHAR(16) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'queued',
 requested_by_uid INT UNSIGNED NOT NULL,
 requested_session_version INT UNSIGNED NOT NULL,
 requested_by VARCHAR(64) NOT NULL,
 requested_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 started_at DATETIME(6) NULL,
 completed_at DATETIME(6) NULL,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 backup_id BIGINT UNSIGNED NULL,
 settings_revision INT UNSIGNED NOT NULL DEFAULT 0,
 destination_id INT UNSIGNED NULL,
 destination_revision INT UNSIGNED NOT NULL DEFAULT 0,
 remote_directory VARCHAR(850) NOT NULL DEFAULT '',
 remote_sha256 CHAR(64) NOT NULL DEFAULT '',
 UNIQUE KEY system_backup_job_key(request_key),
 KEY system_backup_job_queue(status,id),
 CONSTRAINT system_backup_job_action CHECK(action IN ('create','upload')),
 CONSTRAINT system_backup_job_status CHECK(status IN ('queued','running','succeeded','failed')),
 CONSTRAINT system_backup_job_backup FOREIGN KEY(backup_id) REFERENCES system_backups(id) ON DELETE RESTRICT,
 CONSTRAINT system_backup_job_destination FOREIGN KEY(destination_id) REFERENCES archive_destinations(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_worker (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 checked_at DATETIME(6) NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'idle',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 job_id BIGINT UNSIGNED NULL,
 CONSTRAINT system_backup_worker_singleton CHECK(id=1),
 CONSTRAINT system_backup_worker_status CHECK(status IN ('idle','creating','uploading','error'))
) ENGINE=InnoDB;
INSERT IGNORE INTO system_backup_settings(id) VALUES(1);
INSERT IGNORE INTO system_backup_worker(id) VALUES(1);
