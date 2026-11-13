-- Independent account preference. Theme, saved views and device configuration stay unchanged.
CREATE TABLE IF NOT EXISTS user_fortigate_preferences (
 user_id INT UNSIGNED PRIMARY KEY,
 connection_id INT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 CONSTRAINT user_fortigate_preference_owner FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 CONSTRAINT user_fortigate_preference_device FOREIGN KEY(connection_id) REFERENCES fortigate_connections(id) ON DELETE CASCADE
) ENGINE=InnoDB;
