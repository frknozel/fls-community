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
