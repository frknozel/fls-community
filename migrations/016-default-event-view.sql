ALTER TABLE user_event_views
 ADD COLUMN IF NOT EXISTS is_default TINYINT UNSIGNED NULL DEFAULT NULL,
 ADD UNIQUE KEY IF NOT EXISTS event_view_default(user_id,is_default),
 ADD CONSTRAINT event_view_default_value CHECK (is_default IS NULL OR is_default=1);
