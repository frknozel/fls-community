-- Cover group/profile/time aggregation without reading individual event JSON or membership rows.
ALTER TABLE traffic_event_groups
 ADD INDEX summary_cover(group_key,profile,event_at),
 ALGORITHM=INPLACE, LOCK=NONE;
