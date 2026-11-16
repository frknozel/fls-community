<?php
declare(strict_types=1);

/** Set only by the dedicated recovery FastCGI server; HTTP headers are ignored. */
function fls_recovery_rehearsal(): bool {
 return ($_SERVER['FLS_RECOVERY_REHEARSAL']??null)==='1';
}
function fls_recovery_write_error(): array {
 return ['code'=>'recovery_rehearsal_read_only','error'=>'Kurtarma provasında log alımı ve otomatik işler kapalıdır. Bu işlem prova arayüzünden başlatılamaz.'];
}
/** Operational requests must not accumulate behind the masked rehearsal workers. */
function fls_recovery_write_blocked(string $route,string $method): bool {
 return fls_recovery_rehearsal()&&$method==='POST'&&in_array($route,[
  'save_maintenance','request_power','prepare_primary_disk','prepare_mirror_disk','sync_mirror_disk',
  'create_system_backup','upload_system_backup','save_system_backup_settings',
  'save_timestamp_profile','save_timestamp_settings','test_timestamp_profile','timestamp_balance','retry_timestamp','recheck_timestamp',
  'save_archive_tls_settings','save_archive_settings','save_archive_destination','test_archive_destination','retry_archive_delivery',
  'save_fortigate_setup','retest_fortigate_setup','test_credential','cold_query_start',
 ],true);
}
/** Also protect direct management calls that do not pass through public/api.php. */
function fls_recovery_require_writable(): void {
 if(fls_recovery_rehearsal())throw new ManagementError(fls_recovery_write_error()['error'],409);
}
