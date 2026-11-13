USE fls;
CREATE TABLE IF NOT EXISTS av_event_groups (
 event_id BIGINT UNSIGNED PRIMARY KEY,
 group_key BINARY(32) NOT NULL,
 key_complete TINYINT UNSIGNED NOT NULL,
 KEY group_members(group_key,event_id),
 CONSTRAINT av_group_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
