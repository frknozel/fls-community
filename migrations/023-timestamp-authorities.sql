CREATE TABLE IF NOT EXISTS timestamp_profiles (
 provider VARCHAR(16) PRIMARY KEY,
 environment VARCHAR(16) NOT NULL DEFAULT 'production',
 customer_id VARCHAR(16) NOT NULL DEFAULT '',
 secret_cipher TEXT NOT NULL DEFAULT '',
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 check_status VARCHAR(24) NOT NULL DEFAULT 'unconfigured',
 check_code VARCHAR(64) NOT NULL DEFAULT '',
 checked_revision INT UNSIGNED NULL,
 checked_at DATETIME(6) NULL,
 test_requested_at DATETIME(6) NULL,
 balance_requested_at DATETIME(6) NULL,
 balance_status VARCHAR(24) NOT NULL DEFAULT 'unknown',
 balance BIGINT NULL,
 balance_at DATETIME(6) NULL,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;
INSERT IGNORE INTO timestamp_profiles(provider) VALUES('kamusm'),('turktrust');
CREATE TABLE IF NOT EXISTS timestamp_settings (
 id TINYINT UNSIGNED PRIMARY KEY,
 enabled TINYINT NOT NULL DEFAULT 0,
 provider VARCHAR(16) NOT NULL DEFAULT 'kamusm',
 start_manifest_id INT UNSIGNED NOT NULL DEFAULT 0,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_by VARCHAR(64) NOT NULL DEFAULT 'system'
) ENGINE=InnoDB;
INSERT IGNORE INTO timestamp_settings(id) VALUES(1);
CREATE TABLE IF NOT EXISTS timestamp_attempts (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 attempt_key CHAR(32) UNIQUE NOT NULL,
 provider VARCHAR(16) NOT NULL,
 profile_revision INT UNSIGNED NOT NULL,
 kind VARCHAR(16) NOT NULL,
 manifest_id INT UNSIGNED NULL,
 status VARCHAR(32) NOT NULL DEFAULT 'prepared',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 request_sha256 CHAR(64) NOT NULL DEFAULT '',
 response_sha256 CHAR(64) NOT NULL DEFAULT '',
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 KEY timestamp_attempt_history(provider,id),
 CONSTRAINT timestamp_attempt_manifest FOREIGN KEY(manifest_id) REFERENCES archive_manifests(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS timestamp_stamps (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 manifest_id INT UNSIGNED UNIQUE NOT NULL,
 provider VARCHAR(16) NOT NULL,
 profile_revision INT UNSIGNED NOT NULL,
 status VARCHAR(32) NOT NULL DEFAULT 'pending',
 attempt_key CHAR(32) NOT NULL DEFAULT '',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 filename VARCHAR(230) NOT NULL DEFAULT '',
 sha256 CHAR(64) NOT NULL DEFAULT '',
 bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
 stamp_at DATETIME(6) NULL,
 verified_at DATETIME(6) NULL,
 info_json JSON NULL,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 KEY timestamp_stamp_queue(status,manifest_id),
 CONSTRAINT timestamp_stamp_manifest FOREIGN KEY(manifest_id) REFERENCES archive_manifests(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS timestamp_deliveries (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 stamp_id BIGINT UNSIGNED NOT NULL,
 destination_id INT UNSIGNED NOT NULL,
 destination_revision INT UNSIGNED NOT NULL,
 status VARCHAR(24) NOT NULL DEFAULT 'pending',
 attempts INT UNSIGNED NOT NULL DEFAULT 0,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 next_attempt_at DATETIME(6) NULL,
 completed_at DATETIME(6) NULL,
 remote_sha256 CHAR(64) NOT NULL DEFAULT '',
 UNIQUE KEY timestamp_delivery(stamp_id,destination_id,destination_revision),
 CONSTRAINT timestamp_delivery_stamp FOREIGN KEY(stamp_id) REFERENCES timestamp_stamps(id) ON DELETE RESTRICT,
 CONSTRAINT timestamp_delivery_destination FOREIGN KEY(destination_id) REFERENCES archive_destinations(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS timestamp_worker (
 id TINYINT UNSIGNED PRIMARY KEY,
 checked_at DATETIME(6) NOT NULL,
 status VARCHAR(32) NOT NULL,
 error_code VARCHAR(64) NOT NULL DEFAULT ''
) ENGINE=InnoDB;
