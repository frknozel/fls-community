USE fls;
CREATE TABLE IF NOT EXISTS traffic_groups (
 group_key BINARY(32) PRIMARY KEY,
 key_complete TINYINT UNSIGNED NOT NULL,
 outcome VARCHAR(32) NOT NULL,
 subtype VARCHAR(40) NOT NULL,
 policyid INT NOT NULL,
 poluuid VARCHAR(40) NOT NULL,
 srcip VARCHAR(45) NOT NULL,
 reason_code VARCHAR(64) NOT NULL,
 identity_json JSON NOT NULL,
 KEY outcome_groups(outcome,group_key)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS traffic_event_groups (
 event_id BIGINT UNSIGNED PRIMARY KEY,
 group_key BINARY(32) NOT NULL,
 event_at DATETIME(6) NOT NULL,
 profile VARCHAR(160) NOT NULL DEFAULT '',
 KEY group_time(group_key,event_at,event_id),
 KEY event_time(event_at,event_id),
 CONSTRAINT traffic_group_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE RESTRICT,
 CONSTRAINT traffic_group_identity FOREIGN KEY(group_key) REFERENCES traffic_groups(group_key) ON DELETE RESTRICT
) ENGINE=InnoDB;
