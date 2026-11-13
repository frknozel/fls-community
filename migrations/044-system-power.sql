-- Web writes fixed power intent only; a separate privileged worker applies it.
CREATE TABLE IF NOT EXISTS power_requests (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 revision INT UNSIGNED NOT NULL DEFAULT 0,
 action VARCHAR(16) NOT NULL DEFAULT '',
 boot_id CHAR(36) NOT NULL DEFAULT '',
 requested_at DATETIME(6) NULL,
 not_before DATETIME(6) NULL,
 expires_at DATETIME(6) NULL,
 requested_by_uid INT UNSIGNED NULL,
 requested_session_version INT UNSIGNED NULL,
 request_key CHAR(36) NOT NULL DEFAULT '',
 requested_by VARCHAR(100) NOT NULL DEFAULT '',
 CONSTRAINT power_request_singleton CHECK(id=1),
 CONSTRAINT power_request_action CHECK(action IN ('','poweroff','reboot'))
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS power_state (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 attempted_revision INT UNSIGNED NOT NULL DEFAULT 0,
 boot_id CHAR(36) NOT NULL DEFAULT '',
 checked_at DATETIME(6) NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'idle',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 CONSTRAINT power_state_singleton CHECK(id=1),
 CONSTRAINT power_state_status CHECK(status IN ('idle','waiting','submitted','failed','rejected','uncertain'))
) ENGINE=InnoDB;
INSERT IGNORE INTO power_requests(id) VALUES(1);
INSERT IGNORE INTO power_state(id) VALUES(1);
