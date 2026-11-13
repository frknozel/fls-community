-- Derived, rebuildable data only. Original events, memberships and archive files are untouched.
CREATE TABLE IF NOT EXISTS archive_dimensions (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 fingerprint BINARY(32) NOT NULL UNIQUE,
 srcip VARCHAR(45) NOT NULL,
 policyid INT NOT NULL,
 profile VARCHAR(160) NOT NULL,
 subtype VARCHAR(40) NOT NULL,
 outcome VARCHAR(32) NOT NULL,
 reason_code VARCHAR(64) NOT NULL,
 family CHAR(1) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 target_key BINARY(32) NOT NULL,
 reason_key BINARY(32) NOT NULL,
 target_json JSON NOT NULL,
 reason_json JSON NOT NULL,
 KEY source_lookup(srcip), KEY policy_lookup(policyid,subtype),
 KEY profile_lookup(profile), KEY target_lookup(target_key), KEY reason_lookup(reason_key),
 KEY outcome_lookup(outcome)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS archive_event_index (
 event_id BIGINT UNSIGNED PRIMARY KEY,
 dimension_id BIGINT UNSIGNED NOT NULL,
 event_at DATETIME(6) NOT NULL,
 group_key BINARY(32) NULL,
 KEY dimension_time(dimension_id,event_at,group_key),
 KEY event_time(event_at,event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS archive_hour_counts (
 dimension_id BIGINT UNSIGNED NOT NULL,
 hour_at DATETIME NOT NULL,
 records BIGINT UNSIGNED NOT NULL,
 first_event_at DATETIME(6) NOT NULL,
 last_event_at DATETIME(6) NOT NULL,
 PRIMARY KEY(dimension_id,hour_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS archive_group_hours (
 dimension_id BIGINT UNSIGNED NOT NULL,
 group_key BINARY(32) NOT NULL,
 hour_at DATETIME NOT NULL,
 records BIGINT UNSIGNED NOT NULL,
 first_event_at DATETIME(6) NOT NULL,
 last_event_at DATETIME(6) NOT NULL,
 last_record CHAR(46) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 PRIMARY KEY(dimension_id,group_key,hour_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS archive_index_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL,
 event_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
 ready TINYINT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT IGNORE INTO archive_index_state VALUES(1,2,0,0,UTC_TIMESTAMP(6));
