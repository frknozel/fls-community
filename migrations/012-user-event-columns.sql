CREATE TABLE IF NOT EXISTS user_event_columns (
 user_id INT UNSIGNED PRIMARY KEY,
 visible_columns JSON NOT NULL,
 revision BIGINT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 CONSTRAINT event_columns_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 CONSTRAINT event_columns_array CHECK (JSON_TYPE(visible_columns)='ARRAY')
) ENGINE=InnoDB;
