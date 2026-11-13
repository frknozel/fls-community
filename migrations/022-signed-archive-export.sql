CREATE TABLE IF NOT EXISTS archive_export_settings (
 id TINYINT UNSIGNED PRIMARY KEY,
 packaging_enabled TINYINT NOT NULL DEFAULT 1,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_by VARCHAR(64) NOT NULL DEFAULT 'system'
) ENGINE=InnoDB;
INSERT IGNORE INTO archive_export_settings(id) VALUES(1);
CREATE TABLE IF NOT EXISTS archive_packages (
 manifest_id INT UNSIGNED PRIMARY KEY,
 filename VARCHAR(160) NOT NULL,
 sha256 CHAR(64) NOT NULL DEFAULT '',
 bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
 status VARCHAR(24) NOT NULL DEFAULT 'pending',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 created_at DATETIME(6) NULL,
 verified_at DATETIME(6) NULL,
 next_attempt_at DATETIME(6) NULL,
 attempts INT UNSIGNED NOT NULL DEFAULT 0,
 CONSTRAINT archive_package_manifest FOREIGN KEY(manifest_id) REFERENCES archive_manifests(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS archive_destinations (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(100) NOT NULL,
 protocol VARCHAR(8) NOT NULL,
 host VARCHAR(253) NOT NULL,
 port SMALLINT UNSIGNED NOT NULL,
 remote_path VARCHAR(400) NOT NULL,
 share_name VARCHAR(100) NOT NULL DEFAULT '',
 username VARCHAR(120) NOT NULL,
 domain_name VARCHAR(100) NOT NULL DEFAULT '',
 secret_cipher MEDIUMTEXT NOT NULL,
 host_key VARCHAR(100) NOT NULL DEFAULT '',
 enabled TINYINT NOT NULL DEFAULT 0,
 start_manifest_id INT UNSIGNED NOT NULL DEFAULT 1,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 test_requested_at DATETIME(6) NULL,
 checked_at DATETIME(6) NULL,
 checked_revision INT UNSIGNED NULL,
 check_status VARCHAR(24) NOT NULL DEFAULT 'untested',
 check_code VARCHAR(64) NOT NULL DEFAULT '',
 observed_host_key VARCHAR(100) NOT NULL DEFAULT '',
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS archive_deliveries (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 destination_id INT UNSIGNED NOT NULL,
 destination_revision INT UNSIGNED NOT NULL,
 manifest_id INT UNSIGNED NOT NULL,
 status VARCHAR(24) NOT NULL DEFAULT 'pending',
 attempts INT UNSIGNED NOT NULL DEFAULT 0,
 next_attempt_at DATETIME(6) NULL,
 started_at DATETIME(6) NULL,
 completed_at DATETIME(6) NULL,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 remote_sha256 CHAR(64) NOT NULL DEFAULT '',
 UNIQUE KEY delivery_identity(destination_id,destination_revision,manifest_id),
 KEY delivery_queue(status,next_attempt_at),
 CONSTRAINT archive_delivery_destination FOREIGN KEY(destination_id) REFERENCES archive_destinations(id) ON DELETE RESTRICT,
 CONSTRAINT archive_delivery_package FOREIGN KEY(manifest_id) REFERENCES archive_packages(manifest_id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS archive_export_worker (
 id TINYINT UNSIGNED PRIMARY KEY,
 checked_at DATETIME(6) NOT NULL,
 status VARCHAR(32) NOT NULL,
 error_code VARCHAR(64) NOT NULL DEFAULT ''
) ENGINE=InnoDB;
