CREATE DATABASE IF NOT EXISTS fls CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE fls;
CREATE TABLE IF NOT EXISTS source_files (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(80) NOT NULL UNIQUE,
 inode BIGINT UNSIGNED NOT NULL,
 byte_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
 line_number BIGINT UNSIGNED NOT NULL DEFAULT 0,
 observed_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
 invalid_rows BIGINT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS events (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 file_id INT UNSIGNED NOT NULL,
 byte_offset BIGINT UNSIGNED NOT NULL,
 byte_length INT UNSIGNED NOT NULL,
 line_number BIGINT UNSIGNED NOT NULL,
 raw_sha256 BINARY(32) NOT NULL,
 event_at DATETIME(6) NOT NULL,
 received_at DATETIME(6) NOT NULL,
 type VARCHAR(24) NOT NULL,
 subtype VARCHAR(40) NOT NULL,
 action VARCHAR(48) NOT NULL,
 outcome VARCHAR(32) NOT NULL,
 rating_error TINYINT UNSIGNED NOT NULL DEFAULT 0,
 policyid INT NOT NULL DEFAULT -1,
 poluuid VARCHAR(40) NOT NULL DEFAULT '',
 profile VARCHAR(160) NOT NULL DEFAULT '',
 srcip VARCHAR(45) NOT NULL DEFAULT '',
 srcname VARCHAR(128) NOT NULL DEFAULT '',
 dstip VARCHAR(45) NOT NULL DEFAULT '',
 dstport INT UNSIGNED NULL,
 hostname VARCHAR(512) NOT NULL DEFAULT '',
 app VARCHAR(160) NOT NULL DEFAULT '',
 category VARCHAR(160) NOT NULL DEFAULT '',
 reason_code VARCHAR(64) NOT NULL,
 devid VARCHAR(40) NOT NULL DEFAULT '',
 vd VARCHAR(64) NOT NULL DEFAULT '',
 sessionid BIGINT UNSIGNED NULL,
 fields JSON NOT NULL,
 target_fingerprint BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(JSON_OBJECT('kind',CASE WHEN LOWER(TRIM(TRAILING '.' FROM (CASE WHEN subtype='dns' THEN TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.qname')),'')) WHEN subtype='ssl' THEN COALESCE(NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.sni')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.hostname')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.servername')),'')),''),'') WHEN subtype IN ('webfilter','app-ctrl') THEN COALESCE(NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.hostname')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.sni')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.servername')),'')),''),'') ELSE '' END)))<>'' THEN 'domain' WHEN subtype='dns' THEN 'dns_missing' WHEN COALESCE(INET6_NTOA(INET6_ATON(dstip)),TRIM(dstip))<>'' THEN 'ip' ELSE 'missing' END,'value',CASE WHEN LOWER(TRIM(TRAILING '.' FROM (CASE WHEN subtype='dns' THEN TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.qname')),'')) WHEN subtype='ssl' THEN COALESCE(NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.sni')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.hostname')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.servername')),'')),''),'') WHEN subtype IN ('webfilter','app-ctrl') THEN COALESCE(NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.hostname')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.sni')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.servername')),'')),''),'') ELSE '' END)))<>'' THEN LOWER(TRIM(TRAILING '.' FROM (CASE WHEN subtype='dns' THEN TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.qname')),'')) WHEN subtype='ssl' THEN COALESCE(NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.sni')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.hostname')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.servername')),'')),''),'') WHEN subtype IN ('webfilter','app-ctrl') THEN COALESCE(NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.hostname')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.sni')),'')),''),NULLIF(TRIM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.servername')),'')),''),'') ELSE '' END))) WHEN subtype='dns' THEN '' ELSE COALESCE(INET6_NTOA(INET6_ATON(dstip)),TRIM(dstip)) END),256))) VIRTUAL,
 UNIQUE KEY source_position(file_id,byte_offset),
 KEY target_time(target_fingerprint,event_at),
 KEY event_time(event_at,id),
 KEY outcome_time(outcome,event_at),
 KEY policy_time(policyid,event_at),
 KEY profile_time(profile,event_at),
 KEY source_time(srcip,event_at),
 KEY module_time(subtype,event_at),
 KEY device_time(devid,vd,event_at,id),
 KEY session_lookup(devid,vd,sessionid,event_at),
 KEY metric_cover(event_at,outcome,subtype,rating_error),
 KEY current_policy_cover(type,subtype,event_at,policyid,poluuid,profile,devid,vd,outcome,rating_error)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS policies (
 policyid INT NOT NULL,
 poluuid VARCHAR(40) NOT NULL,
 name VARCHAR(160) NOT NULL,
 observed_at DATETIME(6) NOT NULL,
 PRIMARY KEY(policyid,poluuid)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS devices (
 ip VARCHAR(45) PRIMARY KEY,
 name VARCHAR(128) NOT NULL,
 observed_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS hourly_counts (
 dimension BINARY(32) PRIMARY KEY,
 hour_at DATETIME NOT NULL,
 type VARCHAR(24) NOT NULL,
 subtype VARCHAR(40) NOT NULL,
 outcome VARCHAR(32) NOT NULL,
 rating_error TINYINT UNSIGNED NOT NULL,
 policyid INT NOT NULL,
 profile VARCHAR(160) NOT NULL,
 reason_code VARCHAR(64) NOT NULL,
 records BIGINT UNSIGNED NOT NULL,
 KEY hour_at(hour_at),
 KEY outcome_hour(outcome,hour_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS users (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 username VARCHAR(64) UNIQUE NOT NULL,
 password_hash VARCHAR(255) NOT NULL,
 must_change TINYINT NOT NULL DEFAULT 1,
 updated_at DATETIME NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS login_attempts (
 ip VARCHAR(45) PRIMARY KEY,
 failures INT NOT NULL DEFAULT 0,
 last_attempt DATETIME NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS audit_log (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 at DATETIME NOT NULL,
 username VARCHAR(64) NOT NULL,
 ip VARCHAR(45) NOT NULL,
 action VARCHAR(64) NOT NULL,
 detail VARCHAR(500) NOT NULL DEFAULT ''
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS archive_manifests (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 source_file VARCHAR(80) UNIQUE NOT NULL,
 bytes BIGINT UNSIGNED NOT NULL,
 rows_count BIGINT UNSIGNED NOT NULL,
 sha256 CHAR(64) NOT NULL,
 previous_hash CHAR(64) NOT NULL,
 manifest_hash CHAR(64) NOT NULL,
 signed_at DATETIME NOT NULL,
 verified_at DATETIME NULL,
 status VARCHAR(32) NOT NULL,
 manifest_json JSON NOT NULL,
 signature TEXT NOT NULL
) ENGINE=InnoDB;
-- Archive delivery and timestamp baseline includes migrations 022-028.
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
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 tls_trust_pem TEXT NOT NULL DEFAULT '',
 tls_peer_pem TEXT NOT NULL DEFAULT '',
 tls_peer_revision INT UNSIGNED NULL,
 tls_peer_checked_at DATETIME(6) NULL,
 tls_peer_verified_at DATETIME(6) NULL,
 tls_peer_check_code VARCHAR(64) NOT NULL DEFAULT ''
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
 remote_subdir VARCHAR(32) NOT NULL DEFAULT '',
 remote_directory VARCHAR(450) NOT NULL DEFAULT '',
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
 balance_attempted_at DATETIME(6) NULL,
 balance_basis_attempt_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;
INSERT IGNORE INTO timestamp_profiles(provider) VALUES('kamusm'),('turktrust');
CREATE TABLE IF NOT EXISTS timestamp_settings (
 id TINYINT UNSIGNED PRIMARY KEY,
 enabled TINYINT NOT NULL DEFAULT 0,
 provider VARCHAR(16) NOT NULL DEFAULT 'kamusm',
 signing_mode VARCHAR(16) NOT NULL DEFAULT 'provider',
 allow_local_fallback TINYINT NOT NULL DEFAULT 0,
 local_accepted_at DATETIME(6) NULL,
 local_accepted_by VARCHAR(64) NOT NULL DEFAULT '',
 local_acceptance_version INT UNSIGNED NOT NULL DEFAULT 0,
 low_credit_threshold INT UNSIGNED NOT NULL DEFAULT 100,
 stall_minutes INT UNSIGNED NOT NULL DEFAULT 15,
 scope_started_at DATETIME(6) NULL,
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
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
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
 remote_subdir VARCHAR(32) NOT NULL DEFAULT '',
 remote_directory VARCHAR(450) NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS event_notes (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 event_id BIGINT UNSIGNED NOT NULL,
 confirmed_recipient VARCHAR(254) NOT NULL DEFAULT '',
 confirmation_source VARCHAR(120) NOT NULL,
 body TEXT NOT NULL,
 author VARCHAR(64) NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 KEY event_history(event_id,id),
 CONSTRAINT event_notes_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS av_event_groups (
 event_id BIGINT UNSIGNED PRIMARY KEY,
 group_key BINARY(32) NOT NULL,
 key_complete TINYINT UNSIGNED NOT NULL,
 KEY group_members(group_key,event_id),
 CONSTRAINT av_group_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_event_groups (
 event_id BIGINT UNSIGNED PRIMARY KEY,
 group_key BINARY(32) NOT NULL,
 key_complete TINYINT UNSIGNED NOT NULL,
 identity_json JSON NOT NULL,
 KEY group_members(group_key,event_id),
 CONSTRAINT security_group_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

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
 KEY summary_cover(group_key,profile,event_at),
 CONSTRAINT traffic_group_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE RESTRICT,
 CONSTRAINT traffic_group_identity FOREIGN KEY(group_key) REFERENCES traffic_groups(group_key) ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS fg_config_versions (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 device VARCHAR(40) NOT NULL,
 vd VARCHAR(64) NOT NULL,
 component VARCHAR(40) NOT NULL,
 content_sha BINARY(32) NOT NULL,
 content_json JSON NOT NULL,
 created_at DATETIME(6) NOT NULL,
 UNIQUE KEY content_identity(device,vd,component,content_sha)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS fg_config_observations (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 device VARCHAR(40) NOT NULL,
 vd VARCHAR(64) NOT NULL,
 component VARCHAR(40) NOT NULL,
 attempted_at DATETIME(6) NOT NULL,
 observed_at DATETIME(6) NULL,
 version_id BIGINT UNSIGNED NULL,
 error_code VARCHAR(64) NULL,
 stored_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 UNIQUE KEY poll_identity(device,vd,component,attempted_at),
 KEY event_lookup(device,vd,component,observed_at,id),
 KEY attempts(device,vd,component,attempted_at,error_code),
 CONSTRAINT fg_observation_version FOREIGN KEY(version_id) REFERENCES fg_config_versions(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS fg_config_changes (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 observation_id BIGINT UNSIGNED NOT NULL,
 previous_observation_id BIGINT UNSIGNED NULL,
 device VARCHAR(40) NOT NULL,
 vd VARCHAR(64) NOT NULL,
 component VARCHAR(40) NOT NULL,
 object_key BINARY(32) NOT NULL,
 object_kind VARCHAR(24) NOT NULL,
 object_name VARCHAR(512) NOT NULL,
 policyid INT NULL,
 poluuid VARCHAR(40) NULL,
 action VARCHAR(16) NOT NULL,
 last_confirmed_at DATETIME(6) NULL,
 observed_at DATETIME(6) NOT NULL,
 before_json JSON NULL,
 after_json JSON NULL,
 diff_json JSON NOT NULL,
 UNIQUE KEY object_observation(observation_id,object_key),
 KEY change_time(device,vd,observed_at,id),
 KEY object_history(device,vd,object_key,observed_at,id),
 KEY kind_time(device,vd,object_kind,observed_at,id),
 CONSTRAINT fg_change_observation FOREIGN KEY(observation_id) REFERENCES fg_config_observations(id) ON DELETE RESTRICT,
 CONSTRAINT fg_change_previous FOREIGN KEY(previous_observation_id) REFERENCES fg_config_observations(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Derived, rebuildable data only. Original events, memberships and archive files are untouched.
CREATE TABLE IF NOT EXISTS archive_dimensions (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 fingerprint BINARY(32) NOT NULL UNIQUE,
 devid VARCHAR(40) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
 vd VARCHAR(64) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
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
 KEY device_scope(devid,vd), KEY outcome_lookup(outcome)
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
 PRIMARY KEY(dimension_id,group_key,hour_at),
 KEY group_lookup(group_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS archive_index_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL,
 event_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
 ready TINYINT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT IGNORE INTO archive_index_state VALUES(1,3,0,0,UTC_TIMESTAMP(6));

CREATE TABLE IF NOT EXISTS summary_backlog_settings (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 minimum_pending INT UNSIGNED NOT NULL,
 minimum_seconds INT UNSIGNED NOT NULL,
 revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
 updated_at DATETIME(6) NOT NULL,
 updated_by VARCHAR(64) NOT NULL,
 CONSTRAINT backlog_singleton CHECK (id=1),
 CONSTRAINT backlog_pending_range CHECK (minimum_pending BETWEEN 1 AND 100000000),
 CONSTRAINT backlog_duration_range CHECK (minimum_seconds BETWEEN 60 AND 86400 AND MOD(minimum_seconds,60)=0)
) ENGINE=InnoDB;
INSERT IGNORE INTO summary_backlog_settings(id,minimum_pending,minimum_seconds,revision,updated_at,updated_by)
VALUES(1,1000,300,1,UTC_TIMESTAMP(6),'system');

CREATE TABLE IF NOT EXISTS summary_backlog_incidents (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 incident_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
 started_at DATETIME(6) NOT NULL,
 triggered_at DATETIME(6) NOT NULL,
 minimum_pending INT UNSIGNED NOT NULL,
 minimum_seconds INT UNSIGNED NOT NULL,
 settings_revision BIGINT UNSIGNED NULL,
 peak_pending BIGINT UNSIGNED NOT NULL,
 last_pending BIGINT UNSIGNED NOT NULL,
 last_confirmed_at DATETIME(6) NOT NULL,
 last_sample_at DATETIME(6) NOT NULL,
 status VARCHAR(24) NOT NULL,
 resolved_at DATETIME(6) NULL,
 drained_at DATETIME(6) NULL,
 had_measurement_gap TINYINT UNSIGNED NOT NULL DEFAULT 0,
 KEY backlog_trigger(triggered_at,id),
 KEY backlog_resolution(resolved_at,triggered_at),
 CONSTRAINT backlog_incident_status CHECK (status IN ('active','drained','rule_changed','unconfirmed'))
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS summary_backlog_history_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 cursor_file VARCHAR(80) NOT NULL DEFAULT '',
 cursor_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
 cursor_inode BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_sample_at DATETIME(6) NULL,
 coverage_from_at DATETIME(6) NULL,
 open_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 gap_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
 ready TINYINT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NULL
) ENGINE=InnoDB;
INSERT IGNORE INTO summary_backlog_history_state(id) VALUES(1);

CREATE TABLE IF NOT EXISTS user_event_columns (
 user_id INT UNSIGNED PRIMARY KEY,
 visible_columns JSON NOT NULL,
 column_order JSON NULL,
 column_widths JSON NULL,
 pinned_columns JSON NULL,
 revision BIGINT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 CONSTRAINT event_columns_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 CONSTRAINT event_columns_array CHECK (JSON_TYPE(visible_columns)='ARRAY')
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_event_views (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 user_id INT UNSIGNED NOT NULL,
 name VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 configuration JSON NOT NULL,
 revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 is_default TINYINT UNSIGNED NULL DEFAULT NULL,
 sort_order INT UNSIGNED NULL DEFAULT NULL,
 UNIQUE KEY event_view_default(user_id,is_default),
 CONSTRAINT event_view_default_value CHECK (is_default IS NULL OR is_default=1),
 UNIQUE KEY event_view_name(user_id,name),
 CONSTRAINT event_view_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 CONSTRAINT event_view_object CHECK (JSON_TYPE(configuration)='OBJECT')
) ENGINE=InnoDB;

ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS role ENUM('admin','analyst') NOT NULL DEFAULT 'analyst';
ALTER TABLE users ADD COLUMN IF NOT EXISTS enabled TINYINT UNSIGNED NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS revision INT UNSIGNED NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS user_preferences (
 user_id INT UNSIGNED PRIMARY KEY,
 theme ENUM('system','light','dark') NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 CONSTRAINT user_preferences_owner FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS management_lock (id TINYINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB;
INSERT IGNORE INTO management_lock(id) VALUES(1);
CREATE TABLE IF NOT EXISTS fortigate_connections (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(100) NOT NULL,
 serial VARCHAR(40) NOT NULL,
 vdom VARCHAR(64) NOT NULL DEFAULT 'root',
 hostname VARCHAR(253) NOT NULL,
 connect_ip VARCHAR(45) NOT NULL,
 source_ip VARCHAR(45) NOT NULL DEFAULT '',
 port SMALLINT UNSIGNED NOT NULL DEFAULT 443,
 enabled TINYINT UNSIGNED NOT NULL DEFAULT 0,
 is_default TINYINT UNSIGNED NULL DEFAULT NULL,
 legacy_cache TINYINT UNSIGNED NOT NULL DEFAULT 0,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 UNIQUE KEY device_identity(serial,vdom),
 UNIQUE KEY one_default(is_default)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS fortigate_credentials (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 connection_id INT UNSIGNED NOT NULL,
 name VARCHAR(100) NOT NULL,
 purpose ENUM('both','live','config') NOT NULL DEFAULT 'both',
 priority SMALLINT UNSIGNED NOT NULL DEFAULT 100,
 enabled TINYINT UNSIGNED NOT NULL DEFAULT 1,
 secret_cipher TEXT NOT NULL,
 fingerprint CHAR(12) NOT NULL,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 test_requested_at DATETIME(6) NULL,
 checked_at DATETIME(6) NULL,
 checked_revision INT UNSIGNED NULL,
 check_status VARCHAR(24) NOT NULL DEFAULT 'untested',
 check_code VARCHAR(64) NULL,
 last_used_at DATETIME(6) NULL,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 KEY connection_order(connection_id,priority,id),
 CONSTRAINT credential_connection FOREIGN KEY(connection_id) REFERENCES fortigate_connections(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS device_hourly_counts (
 dimension BINARY(32) PRIMARY KEY,
 devid VARCHAR(40) COLLATE utf8mb4_bin NOT NULL,
 vd VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
 hour_at DATETIME NOT NULL,
 type VARCHAR(24) NOT NULL,subtype VARCHAR(40) NOT NULL,outcome VARCHAR(32) NOT NULL,
 rating_error TINYINT NOT NULL,policyid INT NOT NULL,profile VARCHAR(160) NOT NULL,reason_code VARCHAR(64) NOT NULL,
 records BIGINT NOT NULL,
 KEY device_time(devid,vd,hour_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS device_policies (
 devid VARCHAR(40) COLLATE utf8mb4_bin NOT NULL,vd VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
 policyid INT NOT NULL,poluuid VARCHAR(40) NOT NULL,name VARCHAR(160) NOT NULL,observed_at DATETIME(6) NOT NULL,
 PRIMARY KEY(devid,vd,policyid,poluuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS device_sources (
 devid VARCHAR(40) COLLATE utf8mb4_bin NOT NULL,vd VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
 ip VARCHAR(45) NOT NULL,name VARCHAR(128) NOT NULL,observed_at DATETIME(6) NOT NULL,
 PRIMARY KEY(devid,vd,ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Independent account preference. Theme, saved views and device configuration stay unchanged.
CREATE TABLE IF NOT EXISTS user_fortigate_preferences (
 user_id INT UNSIGNED PRIMARY KEY,
 connection_id INT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 CONSTRAINT user_fortigate_preference_owner FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 CONSTRAINT user_fortigate_preference_device FOREIGN KEY(connection_id) REFERENCES fortigate_connections(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Explicit log/API read access. A new account or connection grants no access.
CREATE TABLE IF NOT EXISTS user_fortigate_access (
 user_id INT UNSIGNED NOT NULL,
 connection_id INT UNSIGNED NOT NULL,
 assigned_at DATETIME(6) NOT NULL,
 PRIMARY KEY(user_id,connection_id),
 KEY access_connection(connection_id),
 CONSTRAINT user_fortigate_access_owner FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 CONSTRAINT user_fortigate_access_device FOREIGN KEY(connection_id) REFERENCES fortigate_connections(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS archive_tls_settings (
 id TINYINT UNSIGNED PRIMARY KEY,
 warning_days SMALLINT UNSIGNED NOT NULL DEFAULT 30,
 critical_days SMALLINT UNSIGNED NOT NULL DEFAULT 7,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_by VARCHAR(64) NOT NULL DEFAULT 'system',
 CONSTRAINT archive_tls_settings_singleton CHECK(id=1),
 CONSTRAINT archive_tls_settings_thresholds CHECK(warning_days BETWEEN 1 AND 3650 AND critical_days BETWEEN 1 AND warning_days)
) ENGINE=InnoDB;
INSERT IGNORE INTO archive_tls_settings(id) VALUES(1);

CREATE TABLE IF NOT EXISTS archive_tls_alert_history (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 destination_id INT UNSIGNED NOT NULL,
 destination_name VARCHAR(100) NOT NULL,
 host VARCHAR(253) NOT NULL,
 port SMALLINT UNSIGNED NOT NULL,
 destination_revision INT UNSIGNED NOT NULL,
 alert_code VARCHAR(64) NOT NULL,
 severity VARCHAR(8) NOT NULL,
 message VARCHAR(600) NOT NULL,
 condition_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 warning_days SMALLINT UNSIGNED NOT NULL,
 critical_days SMALLINT UNSIGNED NOT NULL,
 settings_revision INT UNSIGNED NOT NULL,
 certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 expires_at DATETIME(6) NULL,
 days_remaining_at_start INT NULL,
 triggered_at DATETIME(6) NOT NULL,
 last_seen_at DATETIME(6) NOT NULL,
 closed_at DATETIME(6) NULL,
 closure_reason VARCHAR(32) NOT NULL DEFAULT '',
 is_open TINYINT AS (IF(closed_at IS NULL,1,NULL)) VIRTUAL,
 UNIQUE KEY tls_one_open(destination_id,alert_code,is_open),
 KEY tls_history_time(triggered_at,id),
 KEY tls_history_target(destination_id,triggered_at,id),
 KEY tls_history_open(closed_at,triggered_at,id),
 CONSTRAINT tls_history_severity CHECK(severity IN ('warning','error')),
 CONSTRAINT tls_history_thresholds CHECK(warning_days BETWEEN 1 AND 3650 AND critical_days BETWEEN 1 AND warning_days)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS archive_tls_history_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 coverage_from_at DATETIME(6) NULL,
 checked_at DATETIME(6) NULL,
 worker_checked_at DATETIME(6) NULL,
 CONSTRAINT tls_history_singleton CHECK(id=1)
) ENGINE=InnoDB;
INSERT IGNORE INTO archive_tls_history_state(id) VALUES(1);

CREATE TABLE IF NOT EXISTS user_archive_tls_views (
 id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 user_id INT UNSIGNED NOT NULL,
 name VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 configuration JSON NOT NULL,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 UNIQUE KEY archive_tls_view_name(user_id,name),
 CONSTRAINT archive_tls_view_owner FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 CONSTRAINT archive_tls_view_config CHECK(JSON_TYPE(configuration)='OBJECT')
) ENGINE=InnoDB;

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

CREATE TABLE IF NOT EXISTS mail_search_backlog_settings (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 minimum_pending INT UNSIGNED NOT NULL,
 minimum_seconds INT UNSIGNED NOT NULL,
 revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
 updated_at DATETIME(6) NOT NULL,
 updated_by VARCHAR(64) NOT NULL,
 CONSTRAINT mail_search_backlog_singleton CHECK (id=1),
 CONSTRAINT mail_search_backlog_pending_range CHECK (minimum_pending BETWEEN 1 AND 100000000),
 CONSTRAINT mail_search_backlog_duration_range CHECK (minimum_seconds BETWEEN 60 AND 86400 AND MOD(minimum_seconds,60)=0)
) ENGINE=InnoDB;
INSERT IGNORE INTO mail_search_backlog_settings(id,minimum_pending,minimum_seconds,revision,updated_at,updated_by)
VALUES(1,1000,300,1,UTC_TIMESTAMP(6),'system');

CREATE TABLE IF NOT EXISTS mail_search_backlog_incidents (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 incident_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
 started_at DATETIME(6) NOT NULL,
 triggered_at DATETIME(6) NOT NULL,
 minimum_pending INT UNSIGNED NOT NULL,
 minimum_seconds INT UNSIGNED NOT NULL,
 settings_revision BIGINT UNSIGNED NULL,
 peak_pending BIGINT UNSIGNED NOT NULL,
 last_pending BIGINT UNSIGNED NOT NULL,
 last_confirmed_at DATETIME(6) NOT NULL,
 last_sample_at DATETIME(6) NOT NULL,
 status VARCHAR(24) NOT NULL,
 resolved_at DATETIME(6) NULL,
 drained_at DATETIME(6) NULL,
 had_measurement_gap TINYINT UNSIGNED NOT NULL DEFAULT 0,
 KEY backlog_trigger(triggered_at,id),
 KEY backlog_resolution(resolved_at,triggered_at),
 CONSTRAINT mail_search_backlog_incident_status CHECK (status IN ('active','drained','rule_changed','unconfirmed'))
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS mail_search_backlog_history_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 cursor_file VARCHAR(80) NOT NULL DEFAULT '',
 cursor_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
 cursor_inode BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_sample_at DATETIME(6) NULL,
 coverage_from_at DATETIME(6) NULL,
 open_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 gap_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
 ready TINYINT UNSIGNED NOT NULL DEFAULT 0,
 updated_at DATETIME(6) NULL
) ENGINE=InnoDB;
INSERT IGNORE INTO mail_search_backlog_history_state(id) VALUES(1);

CREATE TABLE IF NOT EXISTS fortigate_setup (
 connection_id INT UNSIGNED PRIMARY KEY,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 source_ip VARCHAR(15) NOT NULL,
 peer_ip VARCHAR(15) NOT NULL,
 receiver_ip VARCHAR(15) NOT NULL,
 api_trust_ip VARCHAR(15) NOT NULL,
 syslog_slot TINYINT UNSIGNED NOT NULL DEFAULT 1,
 cli_scope ENUM('single','override') NOT NULL DEFAULT 'single',
 override_confirmed TINYINT UNSIGNED NOT NULL DEFAULT 0,
 receiver_admitted TINYINT UNSIGNED NOT NULL DEFAULT 1,
 baseline_event_id BIGINT UNSIGNED NOT NULL,
 test_started_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 CONSTRAINT setup_connection FOREIGN KEY(connection_id) REFERENCES fortigate_connections(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS fortigate_setup_receipts (
 connection_id INT UNSIGNED PRIMARY KEY,
 setup_revision INT UNSIGNED NOT NULL,
 event_id BIGINT UNSIGNED NOT NULL,
 received_at DATETIME(6) NOT NULL,
 event_at DATETIME(6) NULL,
 peer_ip VARCHAR(45) NOT NULL DEFAULT '',
 status VARCHAR(32) NOT NULL,
 observed_at DATETIME(6) NOT NULL,
 CONSTRAINT receipt_connection FOREIGN KEY(connection_id) REFERENCES fortigate_connections(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS fortigate_setup_state (
 id TINYINT UNSIGNED PRIMARY KEY,
 event_cursor BIGINT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;

-- Product retention policy. No deletion job or remote rotation is enabled here.
CREATE TABLE IF NOT EXISTS retention_settings (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 retention_years TINYINT UNSIGNED NOT NULL DEFAULT 2,
 fast_days SMALLINT UNSIGNED NOT NULL DEFAULT 45,
 revision BIGINT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 updated_by VARCHAR(64) NOT NULL,
 CONSTRAINT retention_singleton CHECK (id=1),
 CONSTRAINT retention_years_range CHECK (retention_years IN (2,3,4)),
 CONSTRAINT retention_fast_days_range CHECK (fast_days IN (45,70,90)),
 CONSTRAINT retention_revision_positive CHECK (revision>=1)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS retention_policy_versions (
 revision BIGINT UNSIGNED NOT NULL PRIMARY KEY,
 retention_years TINYINT UNSIGNED NOT NULL,
 fast_days SMALLINT UNSIGNED NOT NULL,
 effective_at DATETIME(6) NOT NULL,
 recorded_at DATETIME(6) NOT NULL,
 recorded_by VARCHAR(64) NOT NULL,
 archive_existing TINYINT UNSIGNED NOT NULL DEFAULT 0,
 analysis_existing TINYINT UNSIGNED NOT NULL DEFAULT 0,
 KEY retention_effective (effective_at,revision),
 CONSTRAINT retention_archive_existing_flag CHECK (archive_existing IN (0,1)),
 CONSTRAINT retention_analysis_existing_flag CHECK (analysis_existing IN (0,1)),
 CONSTRAINT retention_history_years_range CHECK (retention_years BETWEEN 2 AND 5),
 CONSTRAINT retention_history_fast_range CHECK (fast_days IN (45,70) OR fast_days BETWEEN 90 AND 180)
) ENGINE=InnoDB;
INSERT IGNORE INTO retention_settings(id,retention_years,fast_days,revision,updated_at,updated_by)
VALUES(1,2,45,1,UTC_TIMESTAMP(6),'system');
-- The initial minimum also protects records received before this migration.
INSERT IGNORE INTO retention_policy_versions(revision,retention_years,fast_days,effective_at,recorded_at,recorded_by)
VALUES(1,2,45,'1970-01-01 00:00:00.000000',UTC_TIMESTAMP(6),'system');

-- v0.61 detailed copy catalog. Original records remain unchanged.
CREATE TABLE IF NOT EXISTS cold_snapshots (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 file_id INT UNSIGNED NOT NULL,
 source_file VARCHAR(80) NOT NULL,
 raw_manifest_id INT UNSIGNED NOT NULL,
 raw_manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 purpose ENUM('canary','archive') NOT NULL,
 relative_path VARCHAR(240) NOT NULL UNIQUE,
 payload_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 compressed_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
 expanded_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
 event_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
 note_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
 snapshot_at DATETIME(6) NULL,
 verified_at DATETIME(6) NULL,
 restore_verified_at DATETIME(6) NULL,
 status ENUM('preparing','verified','failed') NOT NULL DEFAULT 'preparing',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 last_attempt_at DATETIME(6) NULL,
 next_attempt_at DATETIME(6) NULL,
 tables_json JSON NULL,
 metadata_json JSON NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 UNIQUE KEY cold_file_purpose(file_id,purpose),
 KEY cold_status_time(status,snapshot_at),
 CONSTRAINT cold_source FOREIGN KEY(file_id) REFERENCES source_files(id) ON DELETE RESTRICT,
 CONSTRAINT cold_raw_manifest FOREIGN KEY(raw_manifest_id) REFERENCES archive_manifests(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS cold_storage_worker (
 id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
 checked_at DATETIME(6) NOT NULL,
 last_success_at DATETIME(6) NULL,
 status ENUM('running','ok','error') NOT NULL,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 fast_days SMALLINT UNSIGNED NOT NULL DEFAULT 45,
 eligible_files BIGINT UNSIGNED NULL,
 eligible_records BIGINT UNSIGNED NULL,
 eligible_bytes BIGINT UNSIGNED NULL,
 raw_files_seen BIGINT UNSIGNED NULL,
 unknown_files BIGINT UNSIGNED NULL,
 completed_files BIGINT UNSIGNED NULL,
 last_snapshot_id BIGINT UNSIGNED NULL,
 read_below_fast_window TINYINT UNSIGNED NOT NULL DEFAULT 1,
 copy_only TINYINT UNSIGNED NOT NULL DEFAULT 1,
 CONSTRAINT cold_worker_singleton CHECK(id=1),
 CONSTRAINT cold_fast_range CHECK(fast_days IN (45,70) OR fast_days BETWEEN 90 AND 180),
 CONSTRAINT cold_no_removal CHECK(read_below_fast_window=1 AND copy_only=1)
) ENGINE=InnoDB;

-- v0.62 verified detailed snapshot device/VDOM coverage.
-- Device/VDOM coverage derived only from a verified immutable detailed snapshot.
CREATE TABLE IF NOT EXISTS cold_snapshot_devices (
 snapshot_id BIGINT UNSIGNED NOT NULL,
 devid VARCHAR(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 vd VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 event_count BIGINT UNSIGNED NOT NULL,
 min_event_at DATETIME(6) NOT NULL,
 max_event_at DATETIME(6) NOT NULL,
 verified_at DATETIME(6) NOT NULL,
 PRIMARY KEY(snapshot_id,devid,vd),
 KEY device_time(devid,vd,min_event_at,max_event_at),
 CONSTRAINT cold_coverage_snapshot FOREIGN KEY(snapshot_id) REFERENCES cold_snapshots(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS archive_integrity_checks (
 manifest_id INT UNSIGNED PRIMARY KEY,
 last_full_verified_at DATETIME(6) NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'pending',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 progress_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
 verification_started_at DATETIME(6) NULL,
 updated_at DATETIME(6) NOT NULL,
 KEY oldest_full_check(last_full_verified_at,manifest_id),
 KEY check_status(status,manifest_id),
 CONSTRAINT integrity_check_manifest FOREIGN KEY(manifest_id) REFERENCES archive_manifests(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS archive_integrity_worker (
 id TINYINT UNSIGNED PRIMARY KEY,
 version INT UNSIGNED NOT NULL DEFAULT 1,
 status VARCHAR(16) NOT NULL DEFAULT 'idle',
 last_started_at DATETIME(6) NULL,
 last_finished_at DATETIME(6) NULL,
 heartbeat_at DATETIME(6) NULL,
 bytes_read BIGINT UNSIGNED NOT NULL DEFAULT 0,
 files_verified INT UNSIGNED NOT NULL DEFAULT 0,
 current_manifest_id INT UNSIGNED NULL,
 max_bytes BIGINT UNSIGNED NOT NULL DEFAULT 536870912,
 max_seconds INT UNSIGNED NOT NULL DEFAULT 45,
 read_bytes_per_second BIGINT UNSIGNED NOT NULL DEFAULT 8388608,
 target_age_days INT UNSIGNED NOT NULL DEFAULT 30,
 last_error_code VARCHAR(64) NOT NULL DEFAULT ''
) ENGINE=InnoDB;
INSERT IGNORE INTO archive_integrity_checks(manifest_id,last_full_verified_at,status,error_code,progress_bytes,updated_at)
 SELECT id,IF(status='verified',verified_at,NULL),
 CASE WHEN status='FAILED' THEN 'FAILED' WHEN status='verified' AND verified_at IS NOT NULL THEN 'verified' ELSE 'pending' END,
 IF(status='FAILED','legacy_integrity_failure',''),0,UTC_TIMESTAMP(6) FROM archive_manifests;
INSERT IGNORE INTO archive_integrity_worker(id) VALUES(1);

-- v0.65 collector maintenance control.
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

-- Web writes fixed power intent only. A separate privileged worker applies it.
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

-- Administrator intents only. Inventory and execution outcomes are root-owned.
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

-- Community second-primary intent. Root journal remains authoritative.
ALTER TABLE disk_management_jobs MODIFY disk_wwn VARCHAR(67) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;
ALTER TABLE disk_management_jobs DROP CONSTRAINT IF EXISTS disk_management_job_action;
ALTER TABLE disk_management_jobs ADD CONSTRAINT disk_management_job_action CHECK(action IN ('prepare','sync','migrate'));
ALTER TABLE disk_management_jobs DROP CONSTRAINT IF EXISTS disk_management_job_confirmation;
ALTER TABLE disk_management_jobs ADD CONSTRAINT disk_management_job_confirmation CHECK(
 (action IN ('prepare','migrate') AND confirmed=1 AND inventory_token IS NOT NULL AND CHAR_LENGTH(inventory_token)=64)
 OR (action='sync' AND confirmed=0 AND inventory_token IS NULL));
ALTER TABLE disk_management_state DROP CONSTRAINT IF EXISTS disk_management_state_status;
ALTER TABLE disk_management_state ADD CONSTRAINT disk_management_state_status CHECK(status IN ('idle','preparing','syncing','migrating','error'));
