<?php
declare(strict_types=1);
/* Community build policy. No activation, lease, expiry or license server. */
const FLS_LICENSE_CORE=['collector','ingest','integrity','timestamp','archive_export','archive_verify','archive_download','retention','authentication','settings'];
const FLS_LICENSE_ADVANCED=['analysis','api_polling','config_comparison','insights'];
final class LicenseRestriction extends RuntimeException {
    public function __construct(public string $denialCode='unknown_feature') {
        parent::__construct('Bu özellik Community sürümünde tanımlı değil.');
    }
}
function license_snapshot(): array {
    return ['schema'=>1,'installation_id'=>null,'mode'=>'community','status'=>'community',
        'checked_at'=>null,'service_configured'=>false,'enforcement'=>false,
        'advanced_allowed'=>true,'features'=>FLS_LICENSE_ADVANCED,'license_id'=>null,
        'license_expires_at'=>null,'lease_issued_at'=>null,'lease_expires_at'=>null,
        'offline_remaining_seconds'=>null,'max_devices'=>null,'errors'=>[],
        'worker_fresh'=>null,'worker_age_seconds'=>null,'max_offline_hours'=>null,
        'verifier'=>'community_policy','build_channel'=>'community',
        'source_license'=>'Apache-2.0'];
}
function license_feature_allowed(string $feature,?array $snapshot=null): bool {
    return in_array($feature,FLS_LICENSE_CORE,true)||in_array($feature,FLS_LICENSE_ADVANCED,true);
}
function license_require_feature(string $feature): void {
    if(!license_feature_allowed($feature))throw new LicenseRestriction();
}
