CREATE TABLE IF NOT EXISTS user_event_views (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 user_id INT UNSIGNED NOT NULL,
 name VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 configuration JSON NOT NULL,
 revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 UNIQUE KEY event_view_name(user_id,name),
 CONSTRAINT event_view_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 CONSTRAINT event_view_object CHECK (JSON_TYPE(configuration)='OBJECT')
) ENGINE=InnoDB;
