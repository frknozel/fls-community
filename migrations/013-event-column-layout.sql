ALTER TABLE user_event_columns
 ADD COLUMN IF NOT EXISTS column_order JSON NULL,
 ADD COLUMN IF NOT EXISTS column_widths JSON NULL;
