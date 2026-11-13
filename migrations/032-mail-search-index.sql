-- Rebuildable, sparse search data only. Original events and signed archives stay intact.
CREATE TABLE IF NOT EXISTS mail_search_events (
 event_id BIGINT UNSIGNED PRIMARY KEY,
 devid VARCHAR(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 vd VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 event_at DATETIME(6) NOT NULL,
 sender MEDIUMTEXT NOT NULL,
 recipient MEDIUMTEXT NOT NULL,
 filename MEDIUMTEXT NOT NULL,
 message_id MEDIUMTEXT NOT NULL,
 KEY device_time(devid,vd,event_at,event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS mail_search_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL,
 event_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
 scanned_records BIGINT UNSIGNED NOT NULL DEFAULT 0,
 indexed_records BIGINT UNSIGNED NOT NULL DEFAULT 0,
 ready TINYINT UNSIGNED NOT NULL DEFAULT 0,
 last_batch_ms INT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NULL
) ENGINE=InnoDB;
INSERT IGNORE INTO mail_search_state(id,version) VALUES(1,1);
