-- Discrete product choices. This migration never removes logs or rewrites old policies.
-- Apply with the updated application. Historical five-year protection remains valid.
ALTER TABLE retention_settings
 DROP CONSTRAINT IF EXISTS retention_years_range,
 DROP CONSTRAINT IF EXISTS retention_fast_days_range,
 MODIFY retention_years TINYINT UNSIGNED NOT NULL DEFAULT 2,
 MODIFY fast_days SMALLINT UNSIGNED NOT NULL DEFAULT 45,
 ADD CONSTRAINT retention_years_range CHECK (retention_years BETWEEN 2 AND 5),
 ADD CONSTRAINT retention_fast_days_range CHECK (fast_days IN (45,70) OR fast_days BETWEEN 90 AND 180);
ALTER TABLE retention_policy_versions
 DROP CONSTRAINT IF EXISTS retention_history_fast_range,
 ADD CONSTRAINT retention_history_fast_range CHECK (fast_days IN (45,70) OR fast_days BETWEEN 90 AND 180);
ALTER TABLE IF EXISTS cold_storage_worker
 DROP CONSTRAINT IF EXISTS cold_fast_range,
 MODIFY fast_days SMALLINT UNSIGNED NOT NULL DEFAULT 45,
 ADD CONSTRAINT cold_fast_range CHECK (fast_days IN (45,70) OR fast_days BETWEEN 90 AND 180);

-- Guard and all policy writes share the settings lock used by the web application.
DROP TEMPORARY TABLE IF EXISTS fls_retention_options_guard;
CREATE TEMPORARY TABLE fls_retention_options_guard (
 passed TINYINT NOT NULL,
 CONSTRAINT retention_options_guard_passed CHECK (passed=1)
);
START TRANSACTION;
SELECT id FROM management_lock WHERE id=1 FOR UPDATE;
SET @fls_options_years=NULL, @fls_options_days=NULL, @fls_options_revision=NULL;
SELECT retention_years,fast_days,revision
 INTO @fls_options_years,@fls_options_days,@fls_options_revision
 FROM retention_settings WHERE id=1 FOR UPDATE;
SET @fls_options_at=UTC_TIMESTAMP(6);
INSERT INTO fls_retention_options_guard(passed)
 SELECT IF(
  @fls_options_years BETWEEN 2 AND 5
  AND (@fls_options_days IN (45,70) OR @fls_options_days BETWEEN 90 AND 180)
  AND @fls_options_revision>=1 AND @fls_options_revision<18446744073709551615
  AND EXISTS(SELECT 1 FROM management_lock WHERE id=1)
  AND (SELECT COUNT(*) FROM retention_policy_versions)=@fls_options_revision
  AND (SELECT MIN(revision) FROM retention_policy_versions)=1
  AND (SELECT MAX(revision) FROM retention_policy_versions)=@fls_options_revision
  AND EXISTS(SELECT 1 FROM retention_policy_versions
    WHERE revision=@fls_options_revision AND retention_years=@fls_options_years
      AND fast_days=@fls_options_days AND effective_at<=@fls_options_at)
  AND NOT EXISTS(SELECT 1 FROM retention_policy_versions WHERE effective_at>@fls_options_at)
  AND NOT EXISTS(SELECT 1 FROM retention_policy_versions v
    JOIN retention_policy_versions previous ON previous.revision=v.revision-1
    WHERE v.effective_at<previous.effective_at),1,0);
SET @fls_options_new_years=LEAST(@fls_options_years,4);
SET @fls_options_new_days=IF(@fls_options_days IN (45,70,90),@fls_options_days,45);
SET @fls_options_changed=(@fls_options_new_years<>@fls_options_years OR @fls_options_new_days<>@fls_options_days);
INSERT INTO retention_policy_versions(revision,retention_years,fast_days,effective_at,recorded_at,recorded_by)
 SELECT @fls_options_revision+1,@fls_options_new_years,@fls_options_new_days,@fls_options_at,@fls_options_at,'schema-upgrade'
 WHERE @fls_options_changed;
UPDATE retention_settings
 SET retention_years=@fls_options_new_years,fast_days=@fls_options_new_days,
     revision=revision+1,updated_at=@fls_options_at,updated_by='schema-upgrade'
 WHERE id=1 AND revision=@fls_options_revision AND @fls_options_changed;
INSERT INTO audit_log(at,username,ip,action,detail)
 SELECT @fls_options_at,'schema-upgrade','127.0.0.1','migrate_retention_options',
  CONCAT('revision=',@fls_options_revision,'->',@fls_options_revision+1,
         CHAR(59),'years=',@fls_options_years,'->',@fls_options_new_years,
         CHAR(59),'fast_days=',@fls_options_days,'->',@fls_options_new_days,
         CHAR(59),'previous_protection=preserved',CHAR(59),'automatic_deletion=off',CHAR(59),'remote_rotation=off')
 WHERE @fls_options_changed;
COMMIT;
DROP TEMPORARY TABLE fls_retention_options_guard;

-- Current settings are strict. The append-only history keeps the legacy vocabulary.
ALTER TABLE retention_settings
 DROP CONSTRAINT IF EXISTS retention_years_range,
 DROP CONSTRAINT IF EXISTS retention_fast_days_range,
 ADD CONSTRAINT retention_years_range CHECK (retention_years IN (2,3,4)),
 ADD CONSTRAINT retention_fast_days_range CHECK (fast_days IN (45,70,90));
