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
