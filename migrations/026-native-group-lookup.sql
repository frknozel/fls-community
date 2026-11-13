-- Only the rebuildable summary receives an online lookup index. Raw events and ingestion are unchanged.
ALTER TABLE archive_group_hours ADD INDEX IF NOT EXISTS group_lookup(group_key), ALGORITHM=INPLACE, LOCK=NONE;
