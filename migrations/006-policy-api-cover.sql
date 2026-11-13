-- Keep current-policy correlation separate from expensive raw JSON scans.
ALTER TABLE events
 ADD INDEX IF NOT EXISTS current_policy_cover(type,subtype,event_at,policyid,poluuid,profile,devid,vd,outcome,rating_error),
 ALGORITHM=INPLACE, LOCK=NONE;
