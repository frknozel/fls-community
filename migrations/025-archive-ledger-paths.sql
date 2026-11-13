ALTER TABLE archive_deliveries
 ADD COLUMN IF NOT EXISTS remote_subdir VARCHAR(32) NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS remote_directory VARCHAR(450) NOT NULL DEFAULT '';
ALTER TABLE timestamp_deliveries
 ADD COLUMN IF NOT EXISTS remote_subdir VARCHAR(32) NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS remote_directory VARCHAR(450) NOT NULL DEFAULT '';
-- Only the current revision has a known base path. Older revisions stay unknown.
UPDATE archive_deliveries j JOIN archive_destinations d ON d.id=j.destination_id AND d.revision=j.destination_revision
 SET j.remote_directory=d.remote_path WHERE j.remote_directory='';
UPDATE timestamp_deliveries j JOIN timestamp_stamps s ON s.id=j.stamp_id JOIN archive_deliveries a ON a.manifest_id=s.manifest_id AND a.destination_id=j.destination_id AND a.destination_revision=j.destination_revision
 SET j.remote_subdir=a.remote_subdir,j.remote_directory=a.remote_directory WHERE j.remote_directory='';
