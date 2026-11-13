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
