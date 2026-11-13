-- Rebuildable allowed-evidence index only. Original events and block indexes are unchanged.
CREATE TABLE IF NOT EXISTS allowed_dimensions (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 fingerprint BINARY(32) NOT NULL UNIQUE,
 devid VARCHAR(40) COLLATE utf8mb4_bin NOT NULL,
 vd VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
 srcip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL,
 policyid INT NOT NULL,
 poluuid VARCHAR(40) COLLATE utf8mb4_bin NOT NULL,
 profile VARCHAR(160) COLLATE utf8mb4_bin NOT NULL,
 subtype VARCHAR(40) COLLATE utf8mb4_bin NOT NULL,
 evidence_kind VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action VARCHAR(48) COLLATE utf8mb4_bin NOT NULL,
 target_kind VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 target_value VARCHAR(512) COLLATE utf8mb4_bin NOT NULL,
 target_key BINARY(32) NOT NULL,
 target_json JSON NOT NULL,
 dstip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL,
 dstport INT UNSIGNED NULL,
 proto VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 app VARCHAR(160) COLLATE utf8mb4_bin NOT NULL,
 category VARCHAR(160) COLLATE utf8mb4_bin NOT NULL,
 risk VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 web_observation TINYINT UNSIGNED NOT NULL DEFAULT 0,
 KEY device_scope(devid,vd), KEY source_lookup(srcip),
 KEY policy_lookup(policyid,poluuid), KEY profile_lookup(profile,subtype),
 KEY target_lookup(target_key), KEY risk_lookup(risk), KEY web_lookup(web_observation,evidence_kind),
 CONSTRAINT allowed_evidence_kind CHECK(evidence_kind IN ('traffic','web','app','dns','tls','security')),
 CONSTRAINT allowed_target_kind CHECK(target_kind IN ('domain','ip','missing')),
 CONSTRAINT allowed_risk CHECK(risk IN ('unknown','low','elevated','medium','high','critical')),
 CONSTRAINT allowed_web_flag CHECK(web_observation IN (0,1)),
 CONSTRAINT allowed_dst_port CHECK(dstport IS NULL OR dstport<=65535)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS allowed_event_index (
 event_id BIGINT UNSIGNED PRIMARY KEY,
 dimension_id BIGINT UNSIGNED NOT NULL,
 event_at DATETIME(6) NOT NULL,
 KEY dimension_time(dimension_id,event_at,event_id),
 KEY event_time(event_at,event_id,dimension_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS allowed_hour_counts (
 dimension_id BIGINT UNSIGNED NOT NULL,
 hour_at DATETIME NOT NULL,
 records BIGINT UNSIGNED NOT NULL,
 first_event_at DATETIME(6) NOT NULL,
 last_event_at DATETIME(6) NOT NULL,
 last_event_id BIGINT UNSIGNED NOT NULL,
 PRIMARY KEY(dimension_id,hour_at), KEY hour_time(hour_at,dimension_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS allowed_index_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL,
 event_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
 scanned_records BIGINT UNSIGNED NOT NULL DEFAULT 0,
 ready TINYINT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NOT NULL,
 CONSTRAINT allowed_state_singleton CHECK(id=1),
 CONSTRAINT allowed_state_version CHECK(version=1),
 CONSTRAINT allowed_state_ready CHECK(ready IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
INSERT IGNORE INTO allowed_index_state VALUES(1,1,0,0,0,UTC_TIMESTAMP(6));
