ALTER TABLE user_event_columns
 ADD COLUMN IF NOT EXISTS pinned_columns JSON NULL;
