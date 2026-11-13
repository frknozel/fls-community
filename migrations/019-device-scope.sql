-- Apply with bin/migrate-device-scope.php. Only derived metadata and online indexes change.
ALTER TABLE archive_dimensions ADD COLUMN IF NOT EXISTS devid VARCHAR(40) COLLATE utf8mb4_bin NOT NULL DEFAULT '', ADD COLUMN IF NOT EXISTS vd VARCHAR(64) COLLATE utf8mb4_bin NOT NULL DEFAULT '', ADD INDEX IF NOT EXISTS device_scope(devid,vd), ALGORITHM=INPLACE, LOCK=NONE;
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

ALTER TABLE events ADD INDEX IF NOT EXISTS device_time(devid,vd,event_at,id), ALGORITHM=INPLACE, LOCK=NONE;
