-- Maintenance requests are applied only by the fixed root service worker.
CREATE TABLE IF NOT EXISTS maintenance_requests (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 requested_mode VARCHAR(16) NOT NULL DEFAULT 'normal',
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 requested_at DATETIME(6) NOT NULL,
 requested_by VARCHAR(100) NOT NULL DEFAULT 'installer',
 CONSTRAINT maintenance_request_singleton CHECK(id=1),
 CONSTRAINT maintenance_requested_mode CHECK(requested_mode IN ('normal','paused')),
 CONSTRAINT maintenance_request_revision CHECK(revision>=1)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS maintenance_state (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 applied_revision INT UNSIGNED NOT NULL DEFAULT 0,
 attempted_revision INT UNSIGNED NOT NULL DEFAULT 0,
 collector_state VARCHAR(16) NOT NULL DEFAULT 'unknown',
 marker_present TINYINT UNSIGNED NOT NULL DEFAULT 0,
 checked_at DATETIME(6) NULL,
 applied_at DATETIME(6) NULL,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 CONSTRAINT maintenance_state_singleton CHECK(id=1),
 CONSTRAINT maintenance_marker_boolean CHECK(marker_present IN (0,1))
) ENGINE=InnoDB;
INSERT IGNORE INTO maintenance_requests(id,requested_mode,revision,requested_at,requested_by)
 VALUES(1,'normal',1,UTC_TIMESTAMP(6),'installer');
INSERT IGNORE INTO maintenance_state(id) VALUES(1);
