-- Administrator intents only; inventory and execution outcomes are root-owned.
CREATE TABLE IF NOT EXISTS disk_management_state (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 boot_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 checked_at DATETIME(6) NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'idle',
 inventory_json LONGTEXT NULL,
 config_revision INT UNSIGNED NOT NULL DEFAULT 0,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 CONSTRAINT disk_management_state_singleton CHECK(id=1),
 CONSTRAINT disk_management_state_status CHECK(status IN ('idle','preparing','syncing','error')),
 CONSTRAINT disk_management_state_json CHECK(inventory_json IS NULL OR JSON_VALID(inventory_json))
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS disk_management_jobs (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 request_key CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action VARCHAR(16) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'queued',
 requested_by_uid INT UNSIGNED NOT NULL,
 requested_session_version INT UNSIGNED NOT NULL,
 requested_by VARCHAR(64) NOT NULL,
 requested_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 expires_at DATETIME(6) NOT NULL DEFAULT (CURRENT_TIMESTAMP(6) + INTERVAL 5 MINUTE),
 started_at DATETIME(6) NULL,
 completed_at DATETIME(6) NULL,
 boot_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 disk_wwn VARCHAR(18) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 disk_serial VARCHAR(128) NOT NULL,
 disk_size_bytes BIGINT UNSIGNED NOT NULL,
 inventory_token CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 config_revision INT UNSIGNED NOT NULL DEFAULT 0,
 confirmed TINYINT UNSIGNED NOT NULL DEFAULT 0,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 result_json LONGTEXT NULL,
 UNIQUE KEY disk_management_request_key(request_key),
 UNIQUE KEY disk_management_prepare_token(inventory_token),
 KEY disk_management_job_queue(status,id),
 CONSTRAINT disk_management_job_action CHECK(action IN ('prepare','sync')),
 CONSTRAINT disk_management_job_status CHECK(status IN ('queued','running','succeeded','failed','rejected')),
 CONSTRAINT disk_management_job_confirmation CHECK(
  (action='prepare' AND confirmed=1 AND inventory_token IS NOT NULL AND CHAR_LENGTH(inventory_token)=64)
  OR (action='sync' AND confirmed=0 AND inventory_token IS NULL)
 ),
 CONSTRAINT disk_management_job_expiry CHECK(expires_at>requested_at),
 CONSTRAINT disk_management_job_result_json CHECK(result_json IS NULL OR JSON_VALID(result_json))
) ENGINE=InnoDB;
INSERT IGNORE INTO disk_management_state(id) VALUES(1);
