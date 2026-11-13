-- Explicit application decisions. Existing revisions keep their original protection.
ALTER TABLE retention_policy_versions
 ADD COLUMN IF NOT EXISTS archive_existing TINYINT UNSIGNED NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS analysis_existing TINYINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE retention_policy_versions
 ADD CONSTRAINT IF NOT EXISTS retention_archive_existing_flag CHECK (archive_existing IN (0,1)),
 ADD CONSTRAINT IF NOT EXISTS retention_analysis_existing_flag CHECK (analysis_existing IN (0,1));
