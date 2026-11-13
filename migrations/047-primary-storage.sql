-- Community second-primary intent. Root journal remains authoritative.
ALTER TABLE disk_management_jobs MODIFY disk_wwn VARCHAR(67) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;
ALTER TABLE disk_management_jobs DROP CONSTRAINT IF EXISTS disk_management_job_action;
ALTER TABLE disk_management_jobs ADD CONSTRAINT disk_management_job_action CHECK(action IN ('prepare','sync','migrate'));
ALTER TABLE disk_management_jobs DROP CONSTRAINT IF EXISTS disk_management_job_confirmation;
ALTER TABLE disk_management_jobs ADD CONSTRAINT disk_management_job_confirmation CHECK(
 (action IN ('prepare','migrate') AND confirmed=1 AND inventory_token IS NOT NULL AND CHAR_LENGTH(inventory_token)=64)
 OR (action='sync' AND confirmed=0 AND inventory_token IS NULL));
ALTER TABLE disk_management_state DROP CONSTRAINT IF EXISTS disk_management_state_status;
ALTER TABLE disk_management_state ADD CONSTRAINT disk_management_state_status CHECK(status IN ('idle','preparing','syncing','migrating','error'));
