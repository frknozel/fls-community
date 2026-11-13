<?php
declare(strict_types=1);
require __DIR__.'/../app/bootstrap.php';
if (!authenticated()) json_response(['error'=>'Oturum açmanız gerekiyor.'],401);
if (($_SESSION['must_change']??true) && !in_array($_GET['route']??'',['save_theme','theme'],true)) json_response(['error'=>'Önce ilk giriş parolanızı değiştirin.'],403);
$username=$_SESSION['username'];session_write_close();
$route=$_GET['route']??'summary';
try {
    // HTTP query parameters are scalar text. Reject arrays before a parser or SQL call.
    foreach($_GET as $value)if(!is_string($value)&&!is_int($value))throw new InvalidArgumentException('Sorgu alanları tek bir metin değeri olmalı.');
    foreach($_GET as $key=>$value){$text=(string)$value;if(strlen($text)>8192||!mb_check_encoding($text,'UTF-8')||str_contains($text,"\0"))throw new InvalidArgumentException('Sorgu metni geçersiz veya fazla uzun.');$_GET[$key]=$text;}
    $route=$_GET['route']??'summary';
    if(in_array($route,['disk_management','prepare_primary_disk','prepare_mirror_disk','sync_mirror_disk'],true)){
        if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Disk yönetimi yönetici yetkisi gerektirir.'],403);
        require_once __DIR__.'/../app/disk-management.php';
        try{
            if($route==='disk_management')json_response(disk_management_snapshot());
            $result=disk_management_write($route,$_POST);$status=$result['http_status']??202;unset($result['http_status']);json_response($result,$status);
        }catch(ManagementError $e){if(db()->inTransaction())db()->rollBack();json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){if(db()->inTransaction())db()->rollBack();error_log('FLS disk management failed: '.get_class($e));json_response(['error'=>'Disk yönetimi işlemi tamamlanamadı. Durumu yenileyin.'],503);}
    }
    if($route==='system_backup_download'){
        require_once __DIR__.'/../app/recovery-download.php';
        recovery_download();
    }
    if(in_array($route,['system_backups','save_system_backup_settings','create_system_backup','upload_system_backup','system_backup_file','backup_encryption_key','system_recovery_kit'],true)){
        if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Sistem yedekleme yönetici yetkisi gerektirir.'],403);
        $read=in_array($route,['system_backups','system_backup_file','backup_encryption_key','system_recovery_kit'],true);$method=$read?'GET':'POST';
        if($_SERVER['REQUEST_METHOD']!==$method){header('Allow: '.$method);json_response(['error'=>'Bu işlem için '.$method.' kullanılmalı.'],405);}
        if(!$read){$token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız.'],403);}
        require_once __DIR__.'/../app/system-backups.php';
        try{
            if($route==='system_backup_file')system_backups_download();
            if($route==='backup_encryption_key')backup_encryption_key_download();
            if($route==='system_recovery_kit'){require_once __DIR__.'/../app/recovery-kit.php';recovery_kit_download();}
            if($route==='system_backups'){db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$data=system_backups_snapshot();db()->commit();json_response($data);}
            $data=system_backups_write($route,$_POST);$status=$data['http_status']??200;unset($data['http_status']);json_response($data,$status);
        }catch(ManagementError $e){if(db()->inTransaction())db()->rollBack();json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){if(db()->inTransaction())db()->rollBack();error_log('FLS system backup operation failed: '.get_class($e));json_response(['error'=>'Sistem yedekleme işlemi tamamlanamadı. Durumu yenileyin.'],503);}
    }
    if(in_array($route,['power_status','request_power'],true)){
        if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Sistem güç yönetimi yönetici yetkisi gerektirir.'],403);
        $read=$route==='power_status';$method=$read?'GET':'POST';
        if($_SERVER['REQUEST_METHOD']!==$method){header('Allow: '.$method);json_response(['error'=>'Bu işlem için '.$method.' kullanılmalı.'],405);}
        if(!$read){$token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız.'],403);}
        require_once __DIR__.'/../app/power.php';
        try{
            if($read){db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$data=power_snapshot();db()->commit();json_response($data);}
            $data=power_save($_POST);$status=$data['http_status']??202;unset($data['http_status']);json_response($data,$status);
        }catch(ManagementError $e){if(db()->inTransaction())db()->rollBack();json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){if(db()->inTransaction())db()->rollBack();error_log('FLS power operation failed: '.get_class($e));json_response(['error'=>'Sistem güç işlemi tamamlanamadı. Durumu yenileyin.'],500);}
    }
    if(in_array($route,['maintenance_status','maintenance','save_maintenance'],true)){
        $read=$route!=='save_maintenance';$method=$read?'GET':'POST';
        if($route!=='maintenance_status'&&($_SESSION['role']??'')!=='admin')json_response(['error'=>'Bakım yönetimi yönetici yetkisi gerektirir.'],403);
        if($_SERVER['REQUEST_METHOD']!==$method){header('Allow: '.$method);json_response(['error'=>'Bu işlem için '.$method.' kullanılmalı.'],405);}
        if(!$read){$token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız.'],403);}
        require_once __DIR__.'/../app/maintenance.php';
        if($read){db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$data=maintenance_snapshot($route==='maintenance_status');db()->commit();json_response($data);}
        $data=maintenance_save($_POST);$status=$data['http_status']??202;unset($data['http_status']);json_response($data,$status);
    }
    if(in_array($route,['timestamp_dashboard','timestamp_status','timestamp_proof','save_timestamp_profile','save_timestamp_settings','test_timestamp_profile','timestamp_balance','retry_timestamp','recheck_timestamp'],true)){
        if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Zaman damgası yönetimi yönetici yetkisi gerektirir.'],403);
        $read=in_array($route,['timestamp_dashboard','timestamp_status','timestamp_proof'],true);$method=$read?'GET':'POST';
        if($_SERVER['REQUEST_METHOD']!==$method){header('Allow: '.$method);json_response(['error'=>'Bu işlem için '.$method.' kullanılmalı.'],405);}
        if(!$read){$token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız.'],403);}
        require __DIR__.'/../app/timestamp.php';
        try{if($route==='timestamp_dashboard')json_response(timestamp_dashboard());if($route==='timestamp_status')json_response(timestamp_snapshot());if($route==='timestamp_proof')timestamp_download();json_response(timestamp_write($route,$_POST));}
        catch(ManagementError $e){json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){error_log('FLS timestamp operation failed: '.get_class($e));json_response(['error'=>'Zaman damgası işlemi tamamlanamadı.'],500);}
    }
    if(in_array($route,['archive_tls_views','archive_tls_view','save_archive_tls_view','delete_archive_tls_view','archive_tls_history_csv','archive_tls_history','archive_tls','archive_ledger','archive_exports','archive_package','save_archive_tls_settings','save_archive_settings','save_archive_destination','test_archive_destination','retry_archive_delivery'],true)){
        if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Arşiv yönetimi yönetici yetkisi gerektirir.'],403);
        $read=in_array($route,['archive_tls_views','archive_tls_view','archive_tls_history','archive_tls','archive_ledger','archive_exports','archive_package'],true);$method=$read?'GET':'POST';
        if($_SERVER['REQUEST_METHOD']!==$method){header('Allow: '.$method);json_response(['error'=>'Bu işlem için '.$method.' kullanılmalı.'],405);}
        if(!$read){$token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız.'],403);}
        require __DIR__.'/../app/archive-export.php';
        try{
            if(in_array($route,['archive_tls_views','archive_tls_view','save_archive_tls_view','delete_archive_tls_view'],true)){
                require __DIR__.'/../app/archive-tls-views.php';$uid=(int)$_SESSION['uid'];
                if($route==='archive_tls_views'){db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$result=archive_tls_views_snapshot($uid);db()->commit();json_response($result);}
                if($route==='archive_tls_view'){db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$result=archive_tls_view_open($uid,$_GET);db()->commit();json_response($result);}
                json_response(archive_tls_view_write($uid,$_POST,$route==='delete_archive_tls_view'));
            }
            if($route==='archive_tls_history_csv'){
                require __DIR__.'/../app/archive-tls-history.php';db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$export=archive_tls_history_export($_POST);db()->commit();
                header('Content-Type: text/csv; charset=utf-8');header('Content-Disposition: attachment; filename="'.$export['filename'].'"');header('Cache-Control: private, no-store');header('X-FLS-Export-Rows: '.$export['rows']);
                fpassthru($export['stream']);fclose($export['stream']);exit;
            }
            if($route==='archive_tls_history'){require __DIR__.'/../app/archive-tls-history.php';db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$history=archive_tls_history_report();db()->commit();json_response($history);}
            if($route==='archive_tls'){require __DIR__.'/../app/archive-tls-history.php';db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$status=archive_tls_alert_snapshot();db()->commit();json_response($status);}
            if($route==='save_archive_tls_settings'){require __DIR__.'/../app/archive-tls.php';$result=archive_tls_settings_save($_POST);$status=$result['http_status']??200;unset($result['http_status']);json_response($result,$status);}
            if($route==='archive_ledger'){require __DIR__.'/../app/archive-ledger.php';json_response(archive_ledger_snapshot());}
            if($route==='archive_exports')json_response(archive_export_snapshot());
            if($route==='archive_package')archive_package_download();
            json_response(archive_export_write($route,$_POST));
        }catch(ArchiveTlsViewConflict $e){json_response(['error'=>$e->getMessage(),'code'=>'tls_view_conflict'],$e->status);}
        catch(ManagementError $e){json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){error_log('FLS archive operation failed: '.get_class($e));json_response(['error'=>'Arşiv işlemi tamamlanamadı. Yeniden deneyin.'],500);}
    }
    if(in_array($route,['cold_storage','cold_snapshot_manifest','cold_snapshot_package','cold_snapshot_public_key'],true)){
        require_once __DIR__.'/../app/cold-storage.php';
        try{
            cold_storage_admin();
            if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');throw new ManagementError('Bu işlem için GET kullanılmalı.',405);}
            if($route==='cold_storage')json_response(cold_storage_snapshot());
            cold_storage_download($route);
        }catch(ManagementError $e){json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){error_log('FLS detailed archive operation failed: '.get_class($e));json_response(['error'=>'Ayrıntılı arşiv durumu alınamadı.'],503);}
    }
    if($route==='license_status'){
        if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Lisans durumu yönetici yetkisi gerektirir.'],403);
        if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');json_response(['error'=>'Bu işlem için GET kullanılmalı.'],405);}
        require_once __DIR__.'/../app/license.php';json_response(license_snapshot());
    }
    if(in_array($route,['retention_policy','preview_retention_policy','save_retention_policy'],true)){
        require_once __DIR__.'/../app/retention.php';
        try{json_response(retention_request($route,$_SERVER['REQUEST_METHOD'],$route==='preview_retention_policy'?array_intersect_key($_GET,array_flip(['retention_years','fast_days','revision'])):$_POST,$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??null));}
        catch(ManagementError $e){if($e->status===405)header('Allow: '.($route!=='save_retention_policy'?'GET':'POST'));json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){error_log('FLS retention operation failed: '.get_class($e));json_response(['error'=>'Saklama ayarları alınamadı. Yeniden deneyin.'],500);}
    }
    if(in_array($route,['fortigate_setup','save_fortigate_setup','retest_fortigate_setup'],true)){
        require __DIR__.'/../app/onboarding.php';
        $method=$route==='fortigate_setup'?'GET':'POST';
        if($_SERVER['REQUEST_METHOD']!==$method){header('Allow: '.$method);json_response(['error'=>'Bu işlem için '.$method.' kullanılmalı.'],405);}
        if($method==='POST'){$token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız.'],403);}
        try{json_response($route==='fortigate_setup'?onboarding_snapshot($_GET):onboarding_write($route,$_POST));}
        catch(ManagementError $e){json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){error_log('FLS onboarding failed: '.get_class($e));json_response(['error'=>'Kurulum durumu alınamadı. Yeniden deneyin.'],500);}
    }
    if(in_array($route,['settings','theme','save_theme','save_fortigate_preference','connection_devices','save_connection','save_credential','delete_credential','set_credential_enabled','test_credential','save_user','reset_user_password'],true)){
        require __DIR__.'/../app/management.php';
        $read=in_array($route,['settings','theme','connection_devices'],true);$method=$read?'GET':'POST';
        if($_SERVER['REQUEST_METHOD']!==$method){header('Allow: '.$method);json_response(['error'=>'Bu işlem için '.$method.' kullanılmalı.'],405);}
        if(!$read){$token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız.'],403);}
        try{
            if($route==='settings')json_response(management_snapshot());
            if($route==='theme')json_response(['theme'=>query('SELECT theme FROM user_preferences WHERE user_id=?',[$_SESSION['uid']])[0]['theme']??null]);
            if($route==='connection_devices'){require_once __DIR__.'/../app/retention.php';json_response(['fast_window_days'=>retention_fast_days(),'devices'=>array_map(fn($d)=>array_intersect_key($d,array_flip(['id','name','serial','vdom','enabled','is_default'])),fg_connections()),'selected_id'=>fg_default_device()['id']]);}
            json_response(management_write($route,$_POST));
        }catch(ManagementError $e){json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){error_log('FLS management operation failed: '.get_class($e));json_response(['error'=>'Ayar işlemi tamamlanamadı. Yeniden deneyin.'],500);}
    }
    if(in_array($route,['event_views','save_event_view','delete_event_view','apply_event_view','set_default_event_view','reorder_event_views'],true)){
        require __DIR__.'/../app/event-views.php';
        $method=$route==='event_views'?'GET':'POST';
        if($_SERVER['REQUEST_METHOD']!==$method){header('Allow: '.$method);json_response(['error'=>'Bu işlem için '.$method.' kullanılmalı.'],405);}
        if($method==='POST'){
            $token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';
            if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız. Sayfayı yenileyin.'],403);
        }
        $uid=(int)$_SESSION['uid'];
        $result=match($route){'event_views'=>event_views_snapshot(event_views_list($uid))+['limit'=>EVENT_VIEWS_LIMIT],
            'reorder_event_views'=>event_views_reorder($uid,$_POST),'set_default_event_view'=>event_view_default($uid,$_POST),'apply_event_view'=>event_view_apply($uid,$_POST),default=>event_view_write($uid,$_POST,$route==='delete_event_view')};
        $status=$result['http_status']??200;unset($result['http_status']);json_response($result,$status);
    }
    if($route==='event_columns'||$route==='save_event_columns'){
        require __DIR__.'/../app/event-columns.php';
        if($route==='save_event_columns'){
            if($_SERVER['REQUEST_METHOD']!=='POST'){header('Allow: POST');json_response(['error'=>'Tercihleri kaydetmek için POST kullanılmalı.'],405);}
            $token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';
            if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız. Sayfayı yenileyin.'],403);
            $result=event_columns_save((int)$_SESSION['uid'],$_POST);$status=$result['http_status']??200;unset($result['http_status']);json_response($result,$status);
        }
        if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');json_response(['error'=>'Tercihleri okumak için GET kullanılmalı.'],405);}
        json_response(event_columns_read((int)$_SESSION['uid']));
    }
    // Account settings do not require a log device. Physical host/archive metrics
    // are global administrative information, never a substitute for device reports.
    $hostRoute=in_array($route,['operations_status','health','telemetry','summary_backlog','backlog_history','mail_search_backlog_history','backlog_settings','save_backlog_settings','mail_search_backlog_settings','save_mail_search_backlog_settings','integrity','manifest'],true);
    if($hostRoute){if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Bu ekran yönetici yetkisi gerektirir.'],403);}
    else fg_require_access();
    require_once __DIR__.'/../app/license.php';
    $licenseDecision=license_snapshot();
    $GLOBALS['FLS_EVENT_FEATURES']=array_combine(FLS_LICENSE_ADVANCED,array_map(fn($feature)=>license_feature_allowed($feature,$licenseDecision),FLS_LICENSE_ADVANCED));
    if(in_array($route,['cold_browse_catalog','cold_query_start','cold_query_status'],true)){
        require_once __DIR__.'/../app/cold-browse.php';
        try{
            $expected=$route==='cold_query_start'?'POST':'GET';if($_SERVER['REQUEST_METHOD']!==$expected){header('Allow: '.$expected);throw new ManagementError('Bu işlem için '.$expected.' kullanılmalı.',405);}
            $data=$route==='cold_browse_catalog'?cold_browse_catalog():cold_browse_query($route);json_response($data,$route==='cold_query_start'?202:200);
        }catch(ManagementError $e){json_response(['error'=>$e->getMessage()],$e->status);}
        catch(Throwable $e){error_log('FLS cold browsing failed: '.get_class($e));json_response(['error'=>'Ayrıntılı arşiv sorgusu tamamlanamadı.'],503);}
    }
    $licensedFeature=match($route){
        'fortigate_live','fortigate_config','vpn'=>'api_polling',
        'config_impact','config_history','config_change','config_observation','change_alerts'=>'config_comparison',
        'investigation_search'=>'insights',
        'allowed_report','allowed_summary','allowed_groups','allowed_group_events','summary','block_summary','policies','source_summary','target_summary','policy_summary','profile_summary','reason_summary','port_summary','port_dashboard','port_records','port_export','traffic_group_events','security_group_events','av_group_events'=>'analysis',
        default=>null
    };
    if($licensedFeature!==null){
        require_once __DIR__.'/../app/license.php';
        if(!$GLOBALS['FLS_EVENT_FEATURES'][$licensedFeature])json_response(['error'=>'Lisans doğrulaması gerekiyor. Log alımı, imza, arşiv ve dışa aktarım sürer.','code'=>'license_restricted','feature'=>$licensedFeature],402);
    }
    if(in_array($route,['events','export'],true)){
        require_once __DIR__.'/../app/license.php';
        if(!event_feature_allowed('analysis'))foreach(['group_av','group_security','group_traffic'] as $key)$_GET[$key]='0';
    }
    if ($route==='add_note') {
        if ($_SERVER['REQUEST_METHOD']!=='POST') { header('Allow: POST');json_response(['error'=>'Not eklemek için POST kullanılmalı.'],405); }
        csrf();
        $id=filter_var($_POST['event_id']??'',FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        if(!$id) json_response(['error'=>'Geçerli bir olay seçin.'],422);
        $values=[];
        foreach(['confirmed_recipient'=>254,'confirmation_source'=>120,'body'=>4000] as $key=>$max) {
            $value=$_POST[$key]??'';
            if(!is_string($value) || !mb_check_encoding($value,'UTF-8') || mb_strlen($value)>$max || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/u',$value)) json_response(['error'=>'Not alanlarından biri geçersiz veya fazla uzun.'],422);
            $values[$key]=trim(str_replace(["\r\n","\r"],"\n",$value));
        }
        if($values['confirmed_recipient']!=='' && !filter_var($values['confirmed_recipient'],FILTER_VALIDATE_EMAIL)) json_response(['error'=>'Doğrulanan alıcı için geçerli tek bir e-posta adresi girin.'],422);
        if($values['confirmed_recipient']==='' && $values['body']==='') json_response(['error'=>'Bir alıcı adresi veya açıklama girin.'],422);
        if($values['confirmation_source']==='') json_response(['error'=>'Doğrulama kaynağını belirtin.'],422);
        require_once __DIR__.'/../app/management.php';
        $noteTransaction=db();$noteTransaction->beginTransaction();
        // Initial HTTP authorization may precede a database lock wait. Recheck
        // the account and explicit device grant before appending evidence.
        $actor=query('SELECT enabled,session_version FROM users WHERE id=? FOR UPDATE',[(int)$_SESSION['uid']])[0]??null;
        if(!$actor||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new ManagementError('Oturum geçerliliğini yitirdi. Yeniden giriş yapın.',403);
        $device=fg_selected_device();
        if(!query('SELECT connection_id FROM user_fortigate_access WHERE user_id=? AND connection_id=? FOR UPDATE',[(int)$_SESSION['uid'],(int)$device['id']]))throw new ManagementError('Bu FortiGate için erişim izniniz yok.',403);
        $event=query('SELECT e.id,e.subtype FROM events e WHERE e.id=? AND '.fg_event_scope('e').' FOR UPDATE',[$id])[0]??null;
        if(!$event)throw new ManagementError('Kayıt bulunamadı.',404);
        if($event['subtype']!=='virus')throw new ManagementError('Bu not alanı antivirüs olayları içindir.',422);
        execute('INSERT INTO event_notes(event_id,confirmed_recipient,confirmation_source,body,author,created_at) VALUES(?,?,?,?,?,UTC_TIMESTAMP(6))',[$id,$values['confirmed_recipient'],$values['confirmation_source'],$values['body'],$username]);
        $noteId=(int)db()->lastInsertId();
        audit('add_event_note','event_id='.$id.';note_id='.$noteId);
        db()->commit();
        json_response(['note'=>query('SELECT id,event_id,confirmed_recipient,confirmation_source,body,author,created_at FROM event_notes WHERE id=?',[$noteId])[0]],201);
    }
    if($route==='backlog_settings'||$route==='save_backlog_settings'){
        require __DIR__.'/../app/backlog-settings.php';
        if($route==='save_backlog_settings'){
            if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Birikme uyarısı ayarları yönetici yetkisi gerektirir.'],403);
            if($_SERVER['REQUEST_METHOD']!=='POST'){header('Allow: POST');json_response(['error'=>'Ayarları kaydetmek için POST kullanılmalı.'],405);}
            $token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';
            if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız. Sayfayı yenileyin.'],403);
            $result=backlog_settings_save($_POST,$username);$status=$result['http_status']??200;unset($result['http_status']);json_response($result,$status);
        }
        if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');json_response(['error'=>'Ayarları okumak için GET kullanılmalı.'],405);}
        json_response(backlog_settings_response());
    }
    if($route==='mail_search_backlog_settings'||$route==='save_mail_search_backlog_settings'){
        require __DIR__.'/../app/mail-search-backlog-settings.php';
        if($route==='save_mail_search_backlog_settings'){
            if(($_SESSION['role']??'')!=='admin')json_response(['error'=>'Birikme uyarısı ayarları yönetici yetkisi gerektirir.'],403);
            if($_SERVER['REQUEST_METHOD']!=='POST'){header('Allow: POST');json_response(['error'=>'Ayarları kaydetmek için POST kullanılmalı.'],405);}
            $token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';
            if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))json_response(['error'=>'Oturum doğrulaması başarısız. Sayfayı yenileyin.'],403);
            $result=mail_search_backlog_settings_save($_POST,$username);$status=$result['http_status']??200;unset($result['http_status']);json_response($result,$status);
        }
        if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');json_response(['error'=>'Ayarları okumak için GET kullanılmalı.'],405);}
        json_response(mail_search_backlog_settings_response());
    }
    if($route==='operations_status'){require_once __DIR__.'/../app/operations.php';json_response(operations_snapshot());}
    if ($route==='health') {
        if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');json_response(['error'=>'Durumu okumak için GET kullanılmalı.'],405);}
        require_once __DIR__.'/../app/integrity-status.php';
        require_once __DIR__.'/../app/maintenance.php';
        require_once __DIR__.'/../app/instance.php';
        require_once __DIR__.'/../app/archive-status.php';
        db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        $archiveIndex=archive_index_status();$mailSearchIndex=mail_search_index_status();
        $health=json_decode(@file_get_contents('/srv/fls-server/metrics/host-health.json')?:'{}',true);
        $files=query('SELECT COUNT(*) files,SUM(byte_offset) indexed_bytes,SUM(observed_size) observed_bytes,SUM(line_number) `lines`,SUM(invalid_rows) invalid_rows,MAX(updated_at) indexed_at FROM source_files')[0];
        $last=query('SELECT event_at,received_at FROM events ORDER BY event_at DESC,id DESC LIMIT 1')[0]??null;
        require __DIR__.'/../app/telemetry.php';
        $software=['nginx'=>$_SERVER['FLS_NGINX_VERSION']??'','php'=>PHP_VERSION,'mariadb'=>query('SELECT VERSION() version')[0]['version']];
        require_once __DIR__.'/../app/archive-tls.php';$archiveTls=archive_tls_health();$archiveIntegrity=archive_integrity_snapshot();$maintenance=maintenance_snapshot();
        db()->commit();
        json_response(['instance'=>fls_instance(),'receiver'=>fls_receiver_state(),'archive_tls'=>$archiveTls,'archive_integrity'=>$archiveIntegrity,'maintenance'=>$maintenance,'collector'=>$health,'telemetry'=>telemetry_latest(),'archive_index'=>$archiveIndex,'mail_search_index'=>$mailSearchIndex,'index'=>$files,'latest_event'=>$last,'now_utc'=>gmdate('c'),'software'=>$software]);
    }
    if($route==='mail_search_backlog_history'){require __DIR__.'/../app/mail-search-backlog-history.php';json_response(mail_search_backlog_history_report());}
    if($route==='backlog_history'){
        require __DIR__.'/../app/backlog-history.php';db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$report=backlog_history_report();db()->commit();json_response($report);
    }
    if($route==='summary_backlog'){require __DIR__.'/../app/backlog-alert.php';$sample=telemetry_latest()??[];json_response(summary_backlog_alert($sample)+['mail_search_index'=>mail_search_backlog_alert($sample)]);}
    if($route==='change_alerts'){require __DIR__.'/../app/change-alerts.php';json_response(configuration_alerts());}
    if($route==='config_impact'){require __DIR__.'/../app/config-impact.php';$data=configuration_impact();$status=$data['http_status']??200;unset($data['http_status']);json_response($data,$status);}
    if(in_array($route,['config_history','config_change','config_observation'],true)){
        require __DIR__.'/../app/fortigate-history.php';
        if($route==='config_history')json_response(fgh_feed());
        $id=filter_var($_GET['id']??'',FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);if(!$id)json_response(['error'=>'Geçerli bir geçmiş kaydı seçin.'],422);
        $page=max(1,min(100000,(int)($_GET['diff_page']??1)));
        if($route==='config_change')$value=fgh_change($id,$page);
        else{$key=$_GET['object']??'';if(!is_string($key)||!preg_match('/^[a-f0-9]{64}$/D',$key))json_response(['error'=>'Geçmiş nesne anahtarı geçersiz.'],422);$value=fgh_observation_object($id,$key,$page);}
        if(!$value)json_response(['error'=>'Geçmiş kaydı bulunamadı.'],404);json_response($value);
    }
    if($route==='fortigate_live')json_response(fg_live_data());
    if($route==='fortigate_config')json_response(fg_cached_config());
    if($route==='telemetry'){require __DIR__.'/../app/telemetry.php';json_response(telemetry_history());}
    if($route==='vpn'){require __DIR__.'/../app/vpn.php';db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');$report=vpn_report();db()->commit();json_response($report);}
    if($route==='investigation_search'){
        if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');json_response(['error'=>'Arama için GET kullanılmalı.'],405);}
        require __DIR__.'/../app/investigation-search.php';
        db()->exec('SET SESSION max_statement_time=5');db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        try{$result=investigation_search();db()->commit();json_response($result);}
        catch(InvestigationSearchUnavailable $e){db()->rollBack();json_response(['error'=>$e->getMessage()],503);}
        catch(PDOException $e){if(db()->inTransaction())db()->rollBack();if((int)($e->errorInfo[1]??0)===1969)json_response(['error'=>'Arama bu aralıkta uzadı. Zaman aralığını daraltıp yeniden deneyin.'],503);throw $e;}
    }
    if ($route==='options') {
        $policies=query('SELECT policyid,poluuid,name FROM '.fg_scoped_table('device_policies').' p ORDER BY policyid');
        if(!array_filter($policies,fn($p)=>(int)$p['policyid']===0) && query('SELECT 1 FROM traffic_groups g WHERE '.fg_identity_scope('g').' AND policyid=0 LIMIT 1')){
            $policies[]=['policyid'=>0,'poluuid'=>'','name'=>'Policy 0'];usort($policies,fn($a,$b)=>(int)$a['policyid']<=>(int)$b['policyid']);
        }
        json_response(['policies'=>$policies,'profiles'=>query("SELECT DISTINCT profile FROM device_hourly_counts h WHERE ".fg_event_scope('h')." AND profile<>'' ORDER BY profile"),'modules'=>query("SELECT DISTINCT subtype FROM device_hourly_counts h WHERE ".fg_event_scope('h')." ORDER BY subtype")]);
    }
    if ($route==='policies') {
        [$where,$p]=conditions();
        db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        $modules=array_column(query("SELECT DISTINCT subtype FROM device_hourly_counts h WHERE ".fg_event_scope('h')." AND type='utm'"),'subtype');$rows=[];
        if($modules){
            $in=implode(',',array_fill(0,count($modules),'?'));
            $rows=query("SELECT e.devid,e.vd,e.policyid,e.poluuid,p.name policy_name,e.profile,e.subtype,MAX(e.id) sample_id,COUNT(*) total,SUM(e.outcome='security_block') blocks,SUM(e.rating_error=1) rating_errors FROM events e FORCE INDEX(current_policy_cover) LEFT JOIN device_policies p ON p.devid=e.devid AND p.vd=e.vd AND p.policyid=e.policyid AND p.poluuid=e.poluuid WHERE $where AND e.type='utm' AND e.subtype IN ($in) GROUP BY e.devid,e.vd,e.policyid,e.poluuid,p.name,e.profile,e.subtype ORDER BY blocks DESC,total DESC LIMIT 200",array_merge($p,$modules));
            if($rows){
                $ids=array_column($rows,'sample_id');$samples=query("SELECT id,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(fields,'$.policytype')),'policy') policy_type FROM events WHERE id IN (".implode(',',array_fill(0,count($ids),'?')).')',$ids);$types=array_column($samples,'policy_type','id');
                foreach($rows as &$row){$row['policy_type']=$types[$row['sample_id']]??'';unset($row['sample_id']);}unset($row);
            }
        }
        db()->commit();
        $config=event_feature_allowed('api_polling')?fg_cached_config():null;foreach($rows as &$row)$row['current_policy']=$config!==null?fg_relation($config,$row,['policytype'=>$row['policy_type']]):null;unset($row);
        json_response(['rows'=>$rows]);
    }
    if($route==='source_summary' || $route==='target_summary' || $route==='policy_summary' || $route==='profile_summary' || $route==='reason_summary'){
        require_once __DIR__.'/../app/source-summary.php';
        db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        $result=match($route){'target_summary'=>target_summary(),'policy_summary'=>policy_summary(),'profile_summary'=>profile_summary(),'reason_summary'=>reason_summary(),default=>source_summary()};db()->commit();json_response($result);
    }
    if(in_array($route,['allowed_report','allowed_summary','allowed_groups','allowed_group_events'],true)){
        require_once __DIR__.'/../app/allowed-traffic.php';
        if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');json_response(['error'=>'Bu işlem için GET kullanılmalı.'],405);}
        try{
            db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
            $result=match($route){'allowed_report'=>['summary'=>allowed_summary(),'groups'=>allowed_groups()],'allowed_summary'=>allowed_summary(),'allowed_groups'=>allowed_groups(),default=>allowed_group_events()};
            db()->commit();json_response($result);
        }catch(AllowedTrafficUnavailable $e){if(db()->inTransaction())db()->rollBack();json_response(['error'=>'İzin verilen trafik indeksi henüz hazır değil.','code'=>'allowed_index_unavailable'],503);}
        catch(Throwable $e){if(db()->inTransaction())db()->rollBack();throw $e;}
    }
    if($route==='block_summary'){
        require __DIR__.'/../app/block-summary.php';
        db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        $result=block_summary();db()->commit();json_response($result);
    }
    if(in_array($route,['port_summary','port_dashboard'],true)){
        require __DIR__.'/../app/port-report.php';
        db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        $result=port_report($route==='port_dashboard');db()->commit();json_response($result);
    }
    if ($route==='summary') {
        require_once __DIR__.'/../app/source-summary.php';
        db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        [$from,$to]=scope();
        $rollup=false;
        [$where,$p]=conditions('e',$rollup);
        $table=$rollup?'hourly_counts':'events';$n=$rollup?'e.records':'1';
        if($metricSource=archive_metric_source($from,$to)){[$metricSql,$p]=$metricSource;$table="($metricSql)";$where='1';$n='e.records';$rollup=true;}
        $metrics=query("SELECT COALESCE(SUM($n),0) total,COALESCE(SUM(IF(e.outcome='security_block',$n,0)),0) blocks,COALESCE(SUM(IF(e.outcome='local_deny',$n,0)),0) local_deny,COALESCE(SUM(IF(e.outcome='policy_deny',$n,0)),0) policy_deny,COALESCE(SUM(IF(e.rating_error=1,$n,0)),0) rating_errors FROM $table e WHERE $where",$p)[0];
        $modules=query("SELECT e.subtype label,SUM($n) n FROM $table e WHERE $where AND e.outcome='security_block' GROUP BY e.subtype ORDER BY n DESC",$p);
        $policies=query("SELECT e.policyid,e.profile,e.subtype,SUM($n) n FROM $table e WHERE $where AND e.outcome='security_block' GROUP BY e.policyid,e.profile,e.subtype ORDER BY n DESC LIMIT 8",$p);
        $names=query('SELECT * FROM '.fg_scoped_table('device_policies').' p');$nameMap=[];foreach($names as $row) $nameMap[$row['policyid']][$row['name']]=1;
        foreach($policies as &$row) $row['policy_name']=implode(' / ',array_keys($nameMap[$row['policyid']]??[]));unset($row);
        $hour=$rollup?'e.hour_at':"DATE_FORMAT(e.event_at,'%Y-%m-%d %H:00:00')";
        $series=query("SELECT $hour hour,SUM($n) total,SUM(IF(e.outcome='security_block',$n,0)) blocks FROM $table e WHERE $where GROUP BY hour ORDER BY hour",$p);
        [$ew,$ep]=conditions();
        require_once __DIR__.'/../app/source-summary.php';
        $dashboard=archive_dashboard_blocks($from,$to);
        if($dashboard){[$blockSql,$blockArgs]=$dashboard;$targets=query("SELECT b.target_json,LOWER(SHA2(b.target_json,256)) target_key,SUM(b.n) n FROM ($blockSql) b GROUP BY target_key ORDER BY n DESC,target_key LIMIT 7",$blockArgs);}
        else $targets=query("SELECT ".source_target_sql('e')." target_json,LOWER(HEX(e.target_fingerprint)) target_key,COUNT(*) n FROM events e WHERE $ew AND e.outcome='security_block' GROUP BY e.target_fingerprint ORDER BY n DESC,target_key LIMIT 7",$ep);
        foreach($targets as &$target){$identity=json_decode($target['target_json'],true,512,JSON_THROW_ON_ERROR);$label=$identity['value']!==''?$identity['value']:($identity['kind']==='dns_missing'?'Sorgu adı logda yok':'Hedef alanı logda yok');$target=['target'=>$identity+['key'=>$target['target_key'],'label'=>$label],'label'=>$label,'n'=>(int)$target['n']];}unset($target);
        if($dashboard){$observed=fg_scoped_table('device_sources');$clients=query("SELECT b.srcip,COALESCE(MAX(d.name),'') srcname,CAST(SUM(b.n) AS UNSIGNED) n FROM ($blockSql) b LEFT JOIN $observed d ON d.ip=b.srcip GROUP BY b.srcip ORDER BY n DESC,b.srcip LIMIT 6",$blockArgs);}
        else $clients=query("SELECT e.srcip,e.srcname,COUNT(*) n FROM events e WHERE $ew AND e.outcome='security_block' GROUP BY e.srcip,e.srcname ORDER BY n DESC LIMIT 6",$ep);
        $hints=[];
        $ssl=$dashboard?query("SELECT COALESCE(SUM(b.n),0) n FROM ($blockSql) b WHERE b.reason_code='certificate_blocklist'",$blockArgs)[0]['n']:query("SELECT COUNT(*) n FROM events e WHERE $ew AND e.outcome='security_block' AND e.reason_code='certificate_blocklist'",$ep)[0]['n'];
        $av=query("SELECT COUNT(*) n,COUNT(DISTINCT JSON_UNQUOTE(JSON_EXTRACT(e.fields,'$.analyticscksum'))) hashes FROM events e FORCE INDEX(current_policy_cover) WHERE $ew AND e.type='utm' AND e.outcome='security_block' AND e.subtype='virus'",$ep)[0];
        if((int)$ssl>0) $hints[]=['level'=>'high','title'=>'Sertifika eşleşmelerini inceleyin','text'=>"Seçili aralıkta $ssl sertifika engeli var. Sertifika açıklaması kaynak programı veya bulaşmayı tek başına kanıtlamaz.",'filter'=>['reason'=>'certificate_blocklist','outcome'=>'security_block']];
        if((int)$av['n']>0) $hints[]=['level'=>'high','title'=>'Antivirüs tekrarlarını ayırın','text'=>$av['n'].' engel kaydı, '.(int)$av['hashes'].' farklı ek karması içeriyor. Kayıt sayısı, farklı e-posta veya enfeksiyon sayısı değildir.','filter'=>['module'=>'virus','outcome'=>'security_block']];
        if((int)$metrics['rating_errors']>0) $hints[]=['level'=>'medium','title'=>'Kategori kararı ile servis hatasını ayırın','text'=>$metrics['rating_errors'].' FortiGuard sorgu hatası gözlendi. Engelleme eylemi ve hata anını birlikte inceleyin.','filter'=>['outcome'=>'rating_error']];
        $hints[]=['level'=>'info','title'=>'Ortak profillerin etkisini görün','text'=>'Aynı güvenlik profili birden fazla policy’de kullanılıyor olabilir. Profil değişikliğinin diğer kullanıcı gruplarını da etkileyebileceğini değerlendirin.','filter'=>[]];
        db()->commit();json_response(compact('metrics','modules','policies','series','targets','clients','hints')+['scope'=>['from_utc'=>$from,'to_utc'=>$to],'generated_at'=>gmdate('c')]);
    }
    $noteMatch='(n.event_id=e.id OR n.event_id IN (SELECT member.event_id FROM av_event_groups member JOIN events ne ON ne.id=member.event_id WHERE member.group_key=ag.group_key AND BINARY ne.devid=BINARY e.devid AND BINARY ne.vd=BINARY e.vd))';
    require_once __DIR__.'/../app/source-summary.php';
    // Security/traffic native keys include device + VDOM; AV keys require an explicit event join.
    $select=source_reason_sql('e')." reason_identity_json,".source_target_sql('e')." target_identity_json,LOWER(HEX(e.target_fingerprint)) target_key,e.id,e.event_at,e.received_at,e.type,e.subtype,e.action,e.outcome,e.rating_error,e.policyid,e.poluuid,e.profile,e.srcip,e.srcname,e.dstip,e.dstport,e.hostname,e.app,e.category,e.reason_code,e.devid,e.vd,e.sessionid,e.fields,p.name policy_name,d.name observed_device_name,".(event_feature_allowed('analysis')?"HEX(tgm.group_key) traffic_group_key,tg.key_complete traffic_key_complete,tg.identity_json traffic_identity_json,HEX(sg.group_key) security_group_key,sg.key_complete security_key_complete,sg.identity_json security_identity_json,(SELECT COUNT(*) FROM security_event_groups member WHERE member.group_key=sg.group_key) security_group_total,HEX(ag.group_key) av_group_key,ag.key_complete group_key_complete,(SELECT COUNT(*) FROM av_event_groups member JOIN events ne ON ne.id=member.event_id WHERE member.group_key=ag.group_key AND BINARY ne.devid=BINARY e.devid AND BINARY ne.vd=BINARY e.vd) av_group_total,":"")."(SELECT COUNT(*) FROM event_notes n WHERE $noteMatch) note_count,(SELECT n.confirmed_recipient FROM event_notes n WHERE $noteMatch AND n.confirmed_recipient<>'' ORDER BY n.id DESC LIMIT 1) confirmed_recipient,(SELECT JSON_ARRAYAGG(DISTINCT n.confirmed_recipient) FROM event_notes n WHERE $noteMatch AND n.confirmed_recipient<>'') confirmed_recipients_json";
    $join='LEFT JOIN device_policies p ON p.devid=e.devid AND p.vd=e.vd AND p.policyid=e.policyid AND p.poluuid=e.poluuid LEFT JOIN device_sources d ON d.devid=e.devid AND d.vd=e.vd AND d.ip=e.srcip LEFT JOIN av_event_groups ag ON ag.event_id=e.id';
    if(event_feature_allowed('analysis'))$join.=' LEFT JOIN security_event_groups sg ON sg.event_id=e.id LEFT JOIN traffic_event_groups tgm ON tgm.event_id=e.id AND e.outcome IN (\'local_deny\',\'policy_deny\') LEFT JOIN traffic_groups tg ON tg.group_key=tgm.group_key';
    if(in_array($route,['port_records','port_export'],true)){
        require __DIR__.'/../app/port-report.php';
        db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        $result=port_records($select,$join,$route==='port_export');db()->commit();
        $status=$result['http_status']??200;unset($result['http_status']);
        if($route!=='port_export'||$status!==200)json_response($result,$status);
        audit('port_export','fg_device='.(int)fg_selected_device()['id'].';records='.$result['total']);
        header('Content-Type: text/csv; charset=utf-8');header('Content-Disposition: attachment; filename="fls-port-denials-'.gmdate('Ymd-His').'.csv"');
        echo "\xEF\xBB\xBF";$out=fopen('php://output','w');$columns=['id','event_at','devid','vd','srcip','srcport','dstip','dstport','protocol','service','policyid','policy_name','poluuid','action','outcome'];fputcsv($out,array_map(fn($k)=>$k==='event_at'?'event_at_utc':$k,$columns),';','"','');
        foreach($result['rows'] as $row){$line=[];foreach($columns as $key){$v=(string)($row[$key]??'');if(preg_match('/^[=+@\-\t\r\n]/',$v))$v="'".$v;$line[]=$v;}fputcsv($out,$line,';','"','');}exit;
    }
    if($route==='traffic_group_events') {
        $id=filter_var($_GET['id']??'',FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        if(!$id)json_response(['error'=>'Geçerli bir olay seçin.'],422);
        $group=traffic_group_info($id);if(!$group)json_response(['error'=>'Ret grubu bulunamadı.'],404);
        $page=max(1,min(1000000,(int)($_GET['page']??1)));$size=50;$offset=($page-1)*$size;
        $ids=array_column(query("SELECT m.event_id FROM traffic_event_groups m JOIN events e ON e.id=m.event_id WHERE ".fg_event_scope('e')." AND m.group_key=UNHEX(?) ORDER BY m.event_at DESC,m.event_id DESC LIMIT $size OFFSET $offset",[$group['key']]),'event_id');$rows=[];
        if($ids){$full=query("SELECT $select FROM events e $join WHERE ".fg_event_scope('e')." AND e.id IN (".implode(',',array_fill(0,count($ids),'?')).')',$ids);$byId=[];foreach(decorate_rows($full) as $row)$byId[$row['id']]=$row;foreach($ids as $eventId)$rows[]=$byId[$eventId];}
        json_response(['rows'=>$rows,'total'=>$group['total_records'],'page'=>$page,'page_size'=>$size,'group'=>$group]);
    }
    if($route==='security_group_events') {
        $id=filter_var($_GET['id']??'',FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        if(!$id)json_response(['error'=>'Geçerli bir olay seçin.'],422);
        $group=security_group_info($id);if(!$group)json_response(['error'=>'Engel grubu bulunamadı.'],404);
        $page=max(1,min(1000000,(int)($_GET['page']??1)));$size=50;$offset=($page-1)*$size;
        $ids=array_column(query("SELECT e.id FROM security_event_groups g JOIN events e ON e.id=g.event_id WHERE ".fg_event_scope('e')." AND g.group_key=UNHEX(?) ORDER BY e.event_at DESC,e.id DESC LIMIT $size OFFSET $offset",[$group['key']]),'id');
        $rows=[];
        if($ids){
            $full=query("SELECT $select FROM events e $join WHERE ".fg_event_scope('e')." AND e.id IN (".implode(',',array_fill(0,count($ids),'?')).')',$ids);
            $byId=[];foreach(decorate_rows($full) as $row)$byId[$row['id']]=$row;
            foreach($ids as $eventId)$rows[]=$byId[$eventId];
        }
        json_response(['rows'=>$rows,'total'=>$group['total_records'],'page'=>$page,'page_size'=>$size,'group'=>$group]);
    }
    if($route==='av_group_events') {
        $id=filter_var($_GET['id']??'',FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        if(!$id)json_response(['error'=>'Geçerli bir olay seçin.'],422);
        $group=av_group_info($id);if(!$group)json_response(['error'=>'Antivirüs grubu bulunamadı.'],404);
        $page=max(1,min(1000000,(int)($_GET['page']??1)));$size=50;$offset=($page-1)*$size;
        $rows=query("SELECT $select FROM events e $join WHERE ".fg_event_scope('e')." AND ag.group_key=UNHEX(?) ORDER BY e.event_at DESC,e.id DESC LIMIT $size OFFSET $offset",[$group['key']]);
        json_response(['rows'=>decorate_rows($rows),'total'=>$group['total_records'],'page'=>$page,'page_size'=>$size,'group'=>$group]);
    }
    if ($route==='events' || $route==='export') {
        $mailSearch=mail_search_requested();if($mailSearch)require_once __DIR__.'/../app/mail-search.php';[$where,$p]=conditions('e',false,true,!$mailSearch);$page=max(1,min(1000,(int)($_GET['page']??1)));$size=50;$offset=($page-1)*$size;
        if(($_GET['q']??'')!==''){$boundedTextSearch=true;db()->exec('SET SESSION max_statement_time=5');}
        if ($route==='export') {
            if($mailSearch){
                db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');[$ids,$args]=mail_search_candidates(array_slice($p,0,2));
                $rows=query("SELECT $select FROM ($ids) mail_ids STRAIGHT_JOIN events e ON e.id=mail_ids.event_id $join WHERE $where ORDER BY e.event_at DESC,e.id DESC LIMIT 10001",array_merge($args,$p));db()->commit();
            }elseif(archive_events_available()){
                db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
                [$af,$at]=scope();$watermark=archive_watermark();[$sql,$args]=archive_summary_query($_GET,$af,$at,$watermark,false,true);
                $count=(int)query("SELECT COALESCE(SUM(n),0) n FROM ($sql) counts",$args)[0]['n'];
                if($count>10000){db()->commit();json_response(['error'=>'Dışa aktarım 10.000 kayıtla sınırlı. Tarih veya filtreyi daraltın.'],422);}
                [$dw,$da]=archive_dimension_filter($_GET);[$tail,$ta]=archive_tail($watermark,$af,$at);[$tw,$tp]=archive_dimension_filter($_GET,'t');
                $ids="SELECT f.event_id id FROM archive_dimensions d STRAIGHT_JOIN archive_event_index f ON f.dimension_id=d.id WHERE $dw AND f.event_at>=? AND f.event_at<? UNION ALL SELECT t.event_id id FROM ($tail) t WHERE $tw";
                $rows=query("SELECT $select FROM ($ids) ids STRAIGHT_JOIN events e ON e.id=ids.id $join ORDER BY e.event_at DESC,e.id DESC LIMIT 10001",array_merge($da,[$af,$at],$ta,$tp));db()->commit();
            }elseif(reason_request_ref()!==null && empty($_GET['q']) && empty($_GET['target_key']) && in_array($_GET['outcome']??'',['all_blocks','security_block','policy_deny','local_deny'],true)){
                $counts=reason_event_candidates($where,$p,0,0);
                if($counts['total_records']>10000)json_response(['error'=>'Dışa aktarım 10.000 kayıtla sınırlı. Tarih veya filtreyi daraltın.'],422);
                $parts=reason_record_parts($where,$p,reason_request_ref());$ids="SELECT m.event_id id ".$parts['traffic_from']." UNION ALL SELECT id FROM (".$parts['other_sql'].") selected";
                $rows=query("SELECT $select FROM ($ids) ids STRAIGHT_JOIN events e ON e.id=ids.id $join ORDER BY e.event_at DESC,e.id DESC LIMIT 10001",array_merge($parts['traffic_args'],$parts['other_args']));
            }else $rows=query("SELECT $select FROM events e $join WHERE $where ORDER BY e.event_at DESC,e.id DESC LIMIT 10001",$p);
            if(count($rows)>10000) json_response(['error'=>'Dışa aktarım 10.000 kayıtla sınırlı. Tarih veya filtreyi daraltın.'],422);
            audit('export','fg_device='.(int)fg_selected_device()['id'].';records='.count($rows));
            header('Content-Type: text/csv; charset=utf-8');header('Content-Disposition: attachment; filename="fls-events-'.gmdate('Ymd-His').'.csv"');
            echo "\xEF\xBB\xBF";$out=fopen('php://output','w');
            $cols=['id','event_at','devid','vd','policyid','policy_name','profile','subtype','action','outcome','srcip','srcname','hostname','category','app','reason_code','mail_sender','mail_recipient','mail_filename','mail_message_id','mail_attachment_hash','mail_hash_field','confirmed_recipient','confirmed_recipients','note_count','av_group_key','av_group_total','security_group_key','security_group_total','traffic_group_key','traffic_group_total','group_target','group_reason'];fputcsv($out,array_map(fn($c)=>$c==='event_at'?'event_at_utc':$c,$cols),';', '"', '');
            foreach(decorate_rows($rows) as $r) {$identity=$r['traffic_group']['identity']??$r['security_group']['identity']??[];$r['group_target']=$identity['target']??'';$r['group_reason']=isset($identity['reason'])?json_encode($identity['reason'],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES):'';$r['confirmed_recipients']=implode(' | ',$r['confirmed_recipients']??[]);foreach($r['mail']??[] as $key=>$value)$r['mail_'.$key]=$value;$line=[];foreach($cols as $c){$v=(string)($r[$c]??'');if(preg_match('/^[=+@\-\t\r\n]/',$v))$v="'".$v;$line[]=$v;}fputcsv($out,$line,';','"',''); }exit;
        }
        if($mailSearch || archive_events_available() || !empty($_GET['block_reason']) || ($_GET['profile']??'')!=='' || !empty($_GET['source']) || !empty($_GET['target_key']) || !empty($_GET['source_reason']) || (($_GET['policy']??'')!=='' && ($_GET['policy_scope']??'')!=='')){
            require_once __DIR__.'/../app/source-summary.php';
            db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
            $report=source_event_candidates($where,$p,$size,$offset);$rows=[];
            if($report['keys']){
                $ids=array_column($report['keys'],'id');$full=query("SELECT $select FROM events e $join WHERE ".fg_event_scope('e')." AND e.id IN (".implode(',',array_fill(0,count($ids),'?')).')',$ids);$byId=[];foreach(decorate_rows($full) as $row)$byId[$row['id']]=$row;
                foreach($report['keys'] as $key){$row=$byId[$key['id']];$field=match($key['group_kind']){'av'=>'av_group','security'=>'security_group','traffic'=>'traffic_group',default=>null};if($field && isset($row[$field]))$row[$field]+=['matched_records'=>(int)$key['matched_records'],'first_event_at'=>$key['first_event_at'],'last_event_at'=>$key['last_event_at']];$rows[]=$row;}
            }
            db()->commit();unset($report['keys']);json_response(['rows'=>$rows,'page'=>$page,'page_size'=>$size]+$report);
        }
        $reasonFamily=block_reason_filter()[0]??'';
        $trafficEnabled=($_GET['group_traffic']??'0')==='1' && in_array($_GET['outcome']??'',['','all_blocks','local_deny','policy_deny'],true) && in_array($_GET['module']??'',['','local','forward'],true) && in_array($_GET['reason']??'',['','local_deny','policy_deny'],true) && !in_array($reasonFamily,['s','a'],true);
        $trafficOnly=$trafficEnabled && (in_array($_GET['outcome']??'',['local_deny','policy_deny'],true) || $reasonFamily==='t');
        $enabled=[];
        if(!$trafficOnly && ($_GET['group_av']??'0')==='1')$enabled[]="SELECT event_id,group_key,'av' group_kind FROM av_event_groups";
        if(!$trafficOnly && ($_GET['group_security']??'0')==='1')$enabled[]="SELECT event_id,group_key,'security' group_kind FROM security_event_groups";
        if($enabled || $trafficEnabled) {
            $limit=$offset+$size;
            $allBlocked=($_GET['outcome']??'')==='all_blocks';
            $traffic=$trafficEnabled?traffic_group_candidates($where,$p,$limit):['keys'=>[],'records'=>0,'groups_count'=>0];
            if($trafficOnly)$count=$traffic['records'];
            elseif($allBlocked && $trafficEnabled)$count=$traffic['records']+(int)query("SELECT COUNT(*) n FROM events e FORCE INDEX(outcome_time) WHERE $where AND e.outcome='security_block'",$p)[0]['n'];
            else $count=(int)query("SELECT COUNT(*) n FROM events e WHERE $where",$p)[0]['n'];
            $total=$count-$traffic['records']+$traffic['groups_count'];$keys=$traffic['keys'];
            if(!$trafficOnly){
                $parts=[];$cte='';$args=$p;$exclusions='';
                if($enabled){
                    $members=implode(' UNION ALL ',$enabled);
                    $grouped=query("WITH enabled AS ($members) SELECT COUNT(*) records,COUNT(DISTINCT g.group_key) groups_count FROM events e JOIN enabled g ON g.event_id=e.id WHERE $where",$p)[0];
                    $total-=(int)$grouped['records']-(int)$grouped['groups_count'];
                    $cte="WITH enabled AS ($members),matched AS (SELECT e.id,e.event_at,g.group_key,g.group_kind FROM enabled g STRAIGHT_JOIN events e ON e.id=g.event_id WHERE $where),stats AS (SELECT group_key,group_kind,COUNT(*) matched_records,MIN(event_at) first_event_at,MAX(event_at) last_event_at FROM matched GROUP BY group_key,group_kind) ";
                    $parts[]="(SELECT MAX(m.id) id,s.last_event_at event_at,s.group_kind,s.matched_records,s.first_event_at,s.last_event_at FROM stats s STRAIGHT_JOIN matched m ON m.group_key=s.group_key AND m.event_at=s.last_event_at GROUP BY s.group_key,s.group_kind,s.matched_records,s.first_event_at,s.last_event_at)";
                    $exclusions.=' AND NOT EXISTS(SELECT 1 FROM enabled g WHERE g.event_id=e.id)';$args=array_merge($p,$p);
                }
                if($trafficEnabled)$exclusions.=' AND NOT EXISTS(SELECT 1 FROM traffic_event_groups m WHERE m.event_id=e.id)';
                // Every supported block receives its membership in the event transaction.
                // Restrict residual rows to the families still displayed individually.
                if($allBlocked && $trafficEnabled){
                    $exclusions.=" AND e.outcome='security_block'";
                    if(($_GET['group_av']??'0')==='1')$exclusions.=" AND e.subtype<>'virus'";
                    if(($_GET['group_security']??'0')==='1')$exclusions.=" AND e.subtype NOT IN ('webfilter','app-ctrl','dns','ssl','ips')";
                }
                $outcome=$_GET['outcome']??'';
                $candidateIndex=in_array($outcome,['security_block','local_deny','policy_deny','all_blocks'],true)?'outcome_time':(!empty($_GET['source'])?'source_time':(!empty($_GET['module'])?'module_time':(!empty($_GET['policy'])?'policy_time':(!empty($_GET['profile'])?'profile_time':'event_time'))));
                $parts[]="(SELECT e.id,e.event_at,NULL group_kind,1 matched_records,e.event_at first_event_at,e.event_at last_event_at FROM events e FORCE INDEX ($candidateIndex) WHERE $where $exclusions ORDER BY e.event_at DESC,e.id DESC LIMIT $limit)";
                $ordinary=query($cte.'SELECT * FROM ('.implode(' UNION ALL ',$parts).") listed ORDER BY event_at DESC,id DESC LIMIT $limit",$args);$keys=array_merge($keys,$ordinary);
            }
            usort($keys,fn($a,$b)=>strcmp($b['event_at'],$a['event_at']) ?: ((int)$b['id']<=>(int)$a['id']));$keys=array_slice($keys,$offset,$size);$rows=[];
            if($keys){
                $ids=array_column($keys,'id');$full=query("SELECT $select FROM events e $join WHERE ".fg_event_scope('e')." AND e.id IN (".implode(',',array_fill(0,count($ids),'?')).')',$ids);$byId=[];foreach(decorate_rows($full) as $row)$byId[$row['id']]=$row;
                foreach($keys as $key){$row=$byId[$key['id']];$field=match($key['group_kind']){'av'=>'av_group','security'=>'security_group','traffic'=>'traffic_group',default=>null};if($field && isset($row[$field]))$row[$field]+=['matched_records'=>(int)$key['matched_records'],'first_event_at'=>$key['first_event_at'],'last_event_at'=>$key['last_event_at']];$rows[]=$row;}
            }
            json_response(['rows'=>$rows,'total'=>$total,'total_records'=>$count,'page'=>$page,'page_size'=>$size,'grouped'=>true]);
        }
        $count=query("SELECT COUNT(*) n FROM events e WHERE $where",$p)[0]['n'];
        $rows=query("SELECT $select FROM events e $join WHERE $where ORDER BY e.event_at DESC,e.id DESC LIMIT $size OFFSET $offset",$p);
        json_response(['rows'=>decorate_rows($rows),'total'=>$count,'total_records'=>(int)$count,'page'=>$page,'page_size'=>$size,'grouped'=>false]);
    }
    if ($route==='detail') {
        $id=filter_var($_GET['id']??'',FILTER_VALIDATE_INT);if(!$id) json_response(['error'=>'Kayıt bulunamadı.'],404);
        $row=query("SELECT $select,e.byte_offset,e.byte_length,e.line_number,HEX(e.raw_sha256) raw_sha256,s.name source_file FROM events e $join JOIN source_files s ON s.id=e.file_id WHERE ".fg_event_scope('e')." AND e.id=?",[$id])[0]??null;
        if(!$row) json_response(['error'=>'Kayıt bulunamadı.'],404);
        $fields=json_decode($row['fields'],true,512,JSON_THROW_ON_ERROR);$raw=null;$verified=false;
        if(preg_match('/^\d{4}-\d{2}-\d{2}-\d{2}\.jsonl$/D',$row['source_file'])) {
            $stream=fopen('/srv/fls-server/raw/'.$row['source_file'],'rb');if($stream){fseek($stream,(int)$row['byte_offset']);$line=fread($stream,(int)$row['byte_length']);fclose($stream);$env=json_decode($line,true);$raw=$env['raw']??null;if($raw!==null)$verified=hash_equals(strtolower($row['raw_sha256']),hash('sha256',$raw));}
        }
        $related=[];
        if(event_feature_allowed('analysis') && (int)$row['sessionid']>0 && $row['srcip']!=='' && $row['dstip']!=='') {
            $when=new DateTimeImmutable($row['event_at'],new DateTimeZone('UTC'));
            $candidates=query("SELECT $select FROM events e $join WHERE ".fg_event_scope('e')." AND e.devid=? AND e.vd=? AND e.sessionid=? AND e.event_at BETWEEN ? AND ? AND e.srcip=? AND e.dstip=? ORDER BY e.event_at,e.id LIMIT 100",[$row['devid'],$row['vd'],$row['sessionid'],$when->modify('-120 seconds')->format('Y-m-d H:i:s.u'),$when->modify('+120 seconds')->format('Y-m-d H:i:s.u'),$row['srcip'],$row['dstip']]);
            preload_traffic_group_stats($candidates);
            foreach($candidates as $candidate) {
                $cf=json_decode($candidate['fields'],true);$match=true;
                foreach(['srcport','dstport','proto','poluuid'] as $k) if(isset($cf[$k],$fields[$k]) && $cf[$k]!==$fields[$k])$match=false;
                if($match)$related[]=decorate($candidate);
            }
        }
        require __DIR__.'/../app/fortigate-history.php';
        audit('view_event','event_id='.$id);
        json_response(['event'=>decorate($row),'fields'=>$fields,'raw'=>$raw,'raw_verified'=>$verified,'related'=>$related,'notes'=>$row['subtype']==='virus'?event_notes($id):[],'av_group'=>event_feature_allowed('analysis')&&$row['subtype']==='virus'?av_group_info($id):null,'security_group'=>event_feature_allowed('analysis')?security_group_info($id):null,'traffic_group'=>event_feature_allowed('analysis')?traffic_group_info($id):null,'fortigate'=>event_feature_allowed('api_polling')?fg_relation(fg_cached_config($row['devid'],$row['vd']),$row,$fields,true):null,'configuration_history'=>event_feature_allowed('config_comparison')?fg_with_event($row,fn()=>fgh_event_safe($row,$fields)):null,'correlation_note'=>event_feature_allowed('analysis')?'Aynı cihaz, VDOM, oturum kimliği ve uçlar; ±120 saniye. Mevcut port/protokol/policy UUID alanları da eşleştirilir.':'Oturum analizi için lisans doğrulaması gerekiyor.']);
    }
    if($route==='integrity') {
        if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');json_response(['error'=>'Durumu okumak için GET kullanılmalı.'],405);}
        require_once __DIR__.'/../app/integrity-status.php';
        db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
        $metrics=query("SELECT COUNT(*) files,COALESCE(SUM(bytes),0) bytes,COALESCE(SUM(rows_count),0) records,COALESCE(SUM(status='FAILED'),0) failures,MAX(verified_at) verified_at FROM archive_manifests")[0];
        $rawJoin=archive_integrity_checks_available()?' LEFT JOIN archive_integrity_checks ic ON ic.manifest_id=m.id':'';
        $rows=query('SELECT m.id,m.source_file,m.bytes,m.rows_count,m.sha256,m.previous_hash,m.manifest_hash,m.signed_at,m.verified_at,m.status,'.archive_integrity_raw_columns().' FROM archive_manifests m'.$rawJoin.' ORDER BY m.source_file DESC');
        $integrity=archive_integrity_snapshot();db()->commit();
        json_response(['metrics'=>$metrics,'rows'=>$rows,'integrity'=>$integrity,'method'=>'SHA-256 + Ed25519 · manifest zinciri','qualified_timestamp'=>false,'note'=>'İmza zinciri ve ham dosyanın tam SHA-256 kontrolü ayrı izlenir. Sağlayıcı zaman damgası ayrı kanıt dosyasında doğrulanır; yerel imza tek başına 5651 uygunluğu beyanı değildir.']);
    }
    if($route==='manifest') {
        $row=query('SELECT manifest_json,signature FROM archive_manifests WHERE id=?',[(int)($_GET['id']??0)])[0]??null;
        if(!$row)json_response(['error'=>'Manifest bulunamadı.'],404);
        header('Content-Disposition: attachment; filename="fls-manifest-'.(int)$_GET['id'].'.json"');json_response(['manifest'=>json_decode($row['manifest_json'],true),'signature'=>$row['signature']]);
    }
    json_response(['error'=>'Bilinmeyen işlem.'],404);
} catch (FortigateAccessError $e) { json_response(['error'=>$e->getMessage(),'code'=>'device_access'],403); }
catch (ManagementError $e) { if(isset($noteTransaction)&&$noteTransaction->inTransaction())$noteTransaction->rollBack();json_response(['error'=>$e->getMessage()],$e->status); }
catch (BacklogSettingsAuthorizationError $e) { json_response(['error'=>$e->getMessage()],403); }
catch (InvalidArgumentException $e) { json_response(['error'=>$e->getMessage()],422); }
catch (MailSearchUnavailable $e) {if(db()->inTransaction())db()->rollBack();json_response(['error'=>$e->getMessage(),'code'=>'search_index'],503);}
catch (Throwable $e) { if(isset($noteTransaction) && $noteTransaction->inTransaction())$noteTransaction->rollBack();if(!empty($boundedTextSearch)&&$e instanceof PDOException&&(int)($e->errorInfo[1]??0)===1969){if(db()->inTransaction())db()->rollBack();json_response(['error'=>'Metin araması bu aralıkta uzadı. Tarih aralığını daraltın veya kaynak, hedef, policy ya da profil filtresi kullanın.'],503);}error_log('FLS: '.$e->getMessage());json_response(['error'=>'İşlem tamamlanamadı. Yeniden deneyin; aramada filtreyi daraltabilirsiniz.'],500); }
