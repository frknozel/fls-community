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
