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
