<?php
declare(strict_types=1);
/* Application-owned settings. Secrets never enter a list, response, audit detail or exception. */
final class ManagementError extends RuntimeException {
    public function __construct(string $message,public int $status=422){parent::__construct($message);}
}
function management_user(): array {
    return ['id'=>(int)$_SESSION['uid'],'username'=>$_SESSION['username'],'display_name'=>$_SESSION['display_name']??'','role'=>$_SESSION['role']??'analyst'];
}
function management_text(array $data,string $key,int $limit,bool $required=true): string {
    $v=$data[$key]??'';
    if(!is_string($v)||!mb_check_encoding($v,'UTF-8')||mb_strlen($v)>$limit||preg_match('/[\x00-\x1f\x7f]/u',$v))throw new ManagementError('Geçersiz alan: '.$key);
    $v=trim($v);if($required&&$v==='')throw new ManagementError('Bu alan gerekli: '.$key);return $v;
}
function management_int(array $data,string $key,int $min=1,int $max=2147483647): int {
    $v=$data[$key]??'';if(!is_string($v)||!preg_match('/^\d{1,10}$/D',$v)||filter_var($v,FILTER_VALIDATE_INT)===false||(int)$v<$min||(int)$v>$max)throw new ManagementError('Geçersiz sayı: '.$key);return (int)$v;
}
function management_bool(array $data,string $key): int {
    $v=$data[$key]??'';if(!in_array($v,['0','1'],true))throw new ManagementError('Geçersiz seçim: '.$key);return (int)$v;
}
function management_enum(array $data,string $key,array $values): string {
    $v=$data[$key]??null;if(!is_string($v)||!in_array($v,$values,true))throw new ManagementError('Geçersiz seçim: '.$key);return $v;
}
function management_password(array $data): string {
    $p=$data['password']??null;
    if(!is_string($p)||!mb_check_encoding($p,'UTF-8')||mb_strlen($p)<14||strlen($p)>256)throw new ManagementError('Parola 14–256 karakter olmalı.');
    return password_hash($p,PASSWORD_ARGON2ID);
}
function management_ip(string $value,bool $optional=false): string {
    if($value===''&&$optional)return '';
    if(!filter_var($value,FILTER_VALIDATE_IP)||!filter_var($value,FILTER_VALIDATE_IP,FILTER_FLAG_NO_RES_RANGE))throw new ManagementError('Geçerli bir unicast IP adresi girin.');
    $packed=inet_pton($value);
    if(str_contains($value,':')){
        if($value==='::1'||str_starts_with(strtolower($value),'fe80:')||str_starts_with(strtolower($value),'ff')||str_starts_with(strtolower($value),'::ffff:'))throw new ManagementError('Bu bağlantı IP adresi kullanılamaz.');
    }else{
        $first=ord($packed[0]);if($first===0||$first===127||$first>=224||substr($packed,0,2)==="\xa9\xfe")throw new ManagementError('Bu bağlantı IP adresi kullanılamaz.');
    }
    return inet_ntop($packed);
}
function management_secret(string $token): string {
    if(!preg_match('~^[A-Za-z0-9._+/=\x7e-]{16,512}$~D',$token))throw new ManagementError('API anahtarı 16–512 karakterlik anahtar değeri olmalı.');
    $key=@file_get_contents('/etc/fls/credential-key');if($key===false||strlen($key)!==32)throw new ManagementError('Anahtar kasası hazır değil.',503);
    $iv=random_bytes(12);$tag='';$cipher=openssl_encrypt($token,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag,'FLS-FortiGate-v1',16);
    if($cipher===false)throw new ManagementError('Anahtar şifrelenemedi.',503);
    return 'v1:'.base64_encode($iv.$cipher.$tag);
}
function management_credentials(): array {
    return query('SELECT id,connection_id,name,purpose,priority,enabled,fingerprint,revision,test_requested_at,checked_at,checked_revision,check_status,check_code,last_used_at,created_at,updated_at FROM fortigate_credentials ORDER BY connection_id,priority,id');
}
function management_devices(): array {return query('SELECT id,name,serial,vdom,hostname,connect_ip,source_ip,port,enabled,is_default,revision,created_at,updated_at FROM fortigate_connections ORDER BY is_default DESC,name,id');}
function management_snapshot(): array {
    $result=['user'=>management_user(),'theme'=>query('SELECT theme,updated_at FROM user_preferences WHERE user_id=?',[$_SESSION['uid']])[0]??null,'admin'=>($_SESSION['role']??'')==='admin'];
    if($result['admin'])$result+=['devices'=>management_devices(),'credentials'=>management_credentials(),'users'=>query('SELECT id,username,display_name,role,enabled,must_change,revision,updated_at FROM users ORDER BY id'),'limits'=>['devices'=>16,'keys_per_device'=>8]];
    if($result['admin']){
        $access=[];foreach(query('SELECT user_id,connection_id FROM user_fortigate_access ORDER BY user_id,connection_id') as $a)$access[(int)$a['user_id']][]=(int)$a['connection_id'];
        foreach($result['users'] as &$user)$user['device_ids']=$access[(int)$user['id']]??[];unset($user);
    }
    return $result;
}
/** The shared management lock must be held before removing an active credential. */
function management_guard_last_credential(array $device,array $credential): void {
    if(!(int)$device['enabled']||!(int)$credential['enabled'])return;
    if(!query('SELECT id FROM fortigate_credentials WHERE connection_id=? AND enabled=1 AND id<>? LIMIT 1',[(int)$device['id'],(int)$credential['id']]))throw new ManagementError('Etkin cihazın son etkin API anahtarı kaldırılamaz. Önce başka bir anahtar ekleyin veya cihazı devre dışı bırakın.',409);
}
function management_write(string $route,array $data): array {
    if($route==='save_fortigate_preference'){
        $id=management_int($data,'connection_id');
        $pdo=db();$pdo->beginTransaction();
        try{
            query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE');
            if(!query('SELECT connection_id FROM user_fortigate_access WHERE user_id=? AND connection_id=?',[(int)$_SESSION['uid'],$id]))throw new ManagementError('Bu FortiGate için erişim izniniz yok.',403);
            execute('INSERT INTO user_fortigate_preferences(user_id,connection_id,updated_at) VALUES(?,?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE connection_id=VALUES(connection_id),updated_at=VALUES(updated_at)',[(int)$_SESSION['uid'],$id]);
            $pdo->commit();
        }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
        return ['fg_device'=>$id,'saved'=>true];
    }
    if($route==='save_theme'){
        $theme=management_enum($data,'theme',['system','light','dark']);
        execute('INSERT INTO user_preferences(user_id,theme,updated_at) VALUES(?,?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE theme=VALUES(theme),updated_at=VALUES(updated_at)',[$_SESSION['uid'],$theme]);
        return ['theme'=>$theme,'saved'=>true];
    }
    if(($_SESSION['role']??'')!=='admin')throw new ManagementError('Bu işlem yönetici yetkisi gerektirir.',403);
    $pdo=db();$pdo->beginTransaction();
    try {
        query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE');
        $actor=query('SELECT role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[$_SESSION['uid']])[0]??null;
        if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new ManagementError('Yönetim yetkiniz değişti. Yeniden oturum açın.',403);
        if($route==='save_connection'){
            $id=isset($data['id'])&&$data['id']!==''?management_int($data,'id'):0;
            $old=$id?(query('SELECT * FROM fortigate_connections WHERE id=? FOR UPDATE',[$id])[0]??null):null;
            if($id&&!$old)throw new ManagementError('Cihaz bulunamadı.',404);
            if($old&&management_int($data,'revision')!==(int)$old['revision'])throw new ManagementError('Cihaz başka bir oturumda değişti. Listeyi yenileyin.',409);
            $name=management_text($data,'name',100);$serial=management_text($data,'serial',40);$vdom=management_text($data,'vdom',64);
            if(!preg_match('/^[A-Za-z0-9_-]{3,40}$/D',$serial)||!preg_match('/^[A-Za-z0-9_.:-]{1,64}$/D',$vdom))throw new ManagementError('Seri numarası veya VDOM geçersiz.');
            if($old&&($old['serial']!==$serial||$old['vdom']!==$vdom))throw new ManagementError('Cihaz kimliği değiştirilemez; farklı cihaz için yeni bağlantı ekleyin.');
            $host=management_text($data,'hostname',253);if(!filter_var($host,FILTER_VALIDATE_IP)&&!filter_var($host,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME))throw new ManagementError('TLS alan adını URL ve port olmadan girin.');
            $ip=management_ip(management_text($data,'connect_ip',45));$source=management_ip(management_text($data,'source_ip',45,false),true);$port=management_int($data,'port',1,65535);$enabled=management_bool($data,'enabled');if($source!==''&&strlen(inet_pton($source))!==strlen(inet_pton($ip)))throw new ManagementError('Bağlantı ve çıkış IP adresleri aynı IP ailesinde olmalı.');$default=management_bool($data,'is_default');
            if($old&&$old['is_default']&&!$default)throw new ManagementError('Önce başka etkin cihazı varsayılan seçin.');
            if($enabled&&(!$id||!(int)(query('SELECT COUNT(*) n FROM fortigate_credentials WHERE connection_id=? AND enabled=1',[$id])[0]['n'])))throw new ManagementError('Cihazı etkinleştirmeden önce en az bir etkin API anahtarı ekleyin.');
            if($default&&!$enabled)throw new ManagementError('Varsayılan cihaz etkin olmalı.');
            if(!$id&&(int)query('SELECT COUNT(*) n FROM fortigate_connections')[0]['n']>=16)throw new ManagementError('Bu sürümde en fazla 16 cihaz eklenebilir.');
            if($default)execute('UPDATE fortigate_connections SET is_default=NULL,revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE is_default=1 AND id<>?',[$id]);
            if($id){
                execute('UPDATE fortigate_connections SET name=?,hostname=?,connect_ip=?,source_ip=?,port=?,enabled=?,is_default=?,revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?',[$name,$host,$ip,$source,$port,$enabled,$default?:null,$id]);
                if($host!==$old['hostname']||$ip!==$old['connect_ip']||$source!==$old['source_ip']||$port!==(int)$old['port'])execute("UPDATE fortigate_credentials SET revision=revision+1,check_status='untested',checked_at=NULL,checked_revision=NULL,test_requested_at=NULL,check_code=NULL WHERE connection_id=?",[$id]);
            }else{
                execute('INSERT INTO fortigate_connections(name,serial,vdom,hostname,connect_ip,source_ip,port,enabled,is_default,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))',[$name,$serial,$vdom,$host,$ip,$source,$port,$enabled,$default?:null]);$id=(int)$pdo->lastInsertId();
            }
            audit('save_connection','connection_id='.$id);
        }elseif($route==='save_credential'){
            $id=isset($data['id'])&&$data['id']!==''?management_int($data,'id'):0;$connection=management_int($data,'connection_id');
            $device=query('SELECT id,enabled FROM fortigate_connections WHERE id=? FOR UPDATE',[$connection])[0]??null;if(!$device)throw new ManagementError('Cihaz bulunamadı.',404);
            $old=$id?(query('SELECT * FROM fortigate_credentials WHERE id=? AND connection_id=? FOR UPDATE',[$id,$connection])[0]??null):null;
            if($id&&!$old)throw new ManagementError('Anahtar bulunamadı.',404);
            if($old&&management_int($data,'revision')!==(int)$old['revision'])throw new ManagementError('Anahtar başka bir oturumda değişti. Listeyi yenileyin.',409);
            $name=management_text($data,'name',100);$purpose=management_enum($data,'purpose',['both','live','config']);$priority=management_int($data,'priority',1,1000);$enabled=management_bool($data,'enabled');
            if($old&&!$enabled)management_guard_last_credential($device,$old);
            $token=$data['token']??'';if(!is_string($token))throw new ManagementError('API anahtarı geçersiz.');
            if($old&&$token===''){$cipher=$old['secret_cipher'];$fingerprint=$old['fingerprint'];}else{$cipher=management_secret($token);$fingerprint=substr(hash('sha256',$token),0,12);}
            if(!$id&&(int)query('SELECT COUNT(*) n FROM fortigate_credentials WHERE connection_id=?',[$connection])[0]['n']>=8)throw new ManagementError('Cihaz başına en fazla 8 anahtar eklenebilir.');
            if($id)execute("UPDATE fortigate_credentials SET name=?,purpose=?,priority=?,enabled=?,secret_cipher=?,fingerprint=?,revision=revision+1,test_requested_at=NULL,checked_at=NULL,checked_revision=NULL,check_status='untested',check_code=NULL,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND connection_id=? AND revision=?",[$name,$purpose,$priority,$enabled,$cipher,$fingerprint,$id,$connection,(int)$old['revision']]);
            else {execute('INSERT INTO fortigate_credentials(connection_id,name,purpose,priority,enabled,secret_cipher,fingerprint,created_at,updated_at) VALUES(?,?,?,?,?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))',[$connection,$name,$purpose,$priority,$enabled,$cipher,$fingerprint]);$id=(int)$pdo->lastInsertId();}
            audit('save_credential','connection_id='.$connection.';credential_id='.$id);
        }elseif(in_array($route,['delete_credential','set_credential_enabled'],true)){
            $id=management_int($data,'id');$connection=management_int($data,'connection_id');$revision=management_int($data,'revision');
            $device=query('SELECT id,enabled FROM fortigate_connections WHERE id=? FOR UPDATE',[$connection])[0]??null;if(!$device)throw new ManagementError('Cihaz bulunamadı.',404);
            $old=query('SELECT id,connection_id,revision,enabled FROM fortigate_credentials WHERE id=? AND connection_id=? FOR UPDATE',[$id,$connection])[0]??null;
            if(!$old)throw new ManagementError('Anahtar bulunamadı.',404);
            if($revision!==(int)$old['revision'])throw new ManagementError('Anahtar başka bir oturumda değişti. Listeyi yenileyin.',409);
            if($route==='delete_credential'){
                management_guard_last_credential($device,$old);
                execute('DELETE FROM fortigate_credentials WHERE id=? AND connection_id=? AND revision=?',[$id,$connection,$revision]);
                audit('delete_credential','connection_id='.$connection.';credential_id='.$id);
            }else{
                $enabled=management_bool($data,'enabled');
                if($enabled!==(int)$old['enabled']){
                    if(!$enabled)management_guard_last_credential($device,$old);
                    execute("UPDATE fortigate_credentials SET enabled=?,revision=revision+1,test_requested_at=NULL,checked_at=NULL,checked_revision=NULL,check_status='untested',check_code=NULL,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND connection_id=? AND revision=?",[$enabled,$id,$connection,$revision]);
                    audit('set_credential_enabled','connection_id='.$connection.';credential_id='.$id.';enabled='.$enabled);
                }
            }
        }elseif($route==='test_credential'){
            $id=management_int($data,'id');if(!query('SELECT id FROM fortigate_credentials WHERE id=?',[$id]))throw new ManagementError('Anahtar bulunamadı.',404);
            execute("UPDATE fortigate_credentials SET test_requested_at=UTC_TIMESTAMP(6),check_status='pending',check_code=NULL WHERE id=?",[$id]);audit('test_credential','credential_id='.$id);
        }elseif($route==='save_user'){
            $id=isset($data['id'])&&$data['id']!==''?management_int($data,'id'):0;$old=$id?(query('SELECT * FROM users WHERE id=? FOR UPDATE',[$id])[0]??null):null;
            if($id&&!$old)throw new ManagementError('Kullanıcı bulunamadı.',404);
            if($old&&management_int($data,'revision')!==(int)$old['revision'])throw new ManagementError('Hesap başka bir oturumda değişti. Listeyi yenileyin.',409);
            $display=management_text($data,'display_name',100,false);$role=management_enum($data,'role',['admin','analyst']);$enabled=management_bool($data,'enabled');
            if($old){
                if($old['role']==='admin'&&(int)$old['enabled']===1&&($role!=='admin'||!$enabled)&&(int)query("SELECT COUNT(*) n FROM users WHERE role='admin' AND enabled=1")[0]['n']<=1)throw new ManagementError('Son etkin yönetici devre dışı bırakılamaz veya analiste çevrilemez.',409);
                $revoke=$role!==$old['role']||$enabled!==(int)$old['enabled'];
                execute('UPDATE users SET display_name=?,role=?,enabled=?,session_version=session_version+?,revision=revision+1,updated_at=UTC_TIMESTAMP() WHERE id=?',[$display,$role,$enabled,(int)$revoke,$id]);
            }else{
                $username=management_text($data,'username',64);if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.@-]{2,63}$/D',$username))throw new ManagementError('Kullanıcı adı 3–64 karakter, harf/rakam ve . _ @ - içermeli.');
                $hash=management_password($data);execute('INSERT INTO users(username,password_hash,display_name,role,enabled,must_change,updated_at) VALUES(?,?,?,?,?,1,UTC_TIMESTAMP())',[$username,$hash,$display,$role,$enabled]);$id=(int)$pdo->lastInsertId();
            }
            if(array_key_exists('device_ids',$data)){
                $encoded=$data['device_ids'];
                if(!is_string($encoded)||strlen($encoded)>512)throw new ManagementError('FortiGate erişim listesi geçersiz.');
                try{$ids=json_decode($encoded,false,8,JSON_THROW_ON_ERROR);}catch(JsonException $e){throw new ManagementError('FortiGate erişim listesi geçersiz.');}
                if(!is_array($ids)||!array_is_list($ids)||count($ids)>16)throw new ManagementError('FortiGate erişim listesi geçersiz.');
                foreach($ids as $deviceId)if(!is_int($deviceId)||$deviceId<1||$deviceId>2147483647)throw new ManagementError('FortiGate erişim listesi geçersiz.');
                $ids=array_values(array_unique($ids));sort($ids);
                if($ids&&count(query('SELECT id FROM fortigate_connections WHERE id IN ('.implode(',',array_fill(0,count($ids),'?')).')',$ids))!==count($ids))throw new ManagementError('Seçilen FortiGate değişti. Listeyi yenileyin.',409);
                $before=array_map('intval',array_column(query('SELECT connection_id FROM user_fortigate_access WHERE user_id=? ORDER BY connection_id',[$id]),'connection_id'));
                foreach(array_diff($before,$ids) as $deviceId)execute('DELETE FROM user_fortigate_access WHERE user_id=? AND connection_id=?',[$id,$deviceId]);
                foreach(array_diff($ids,$before) as $deviceId)execute('INSERT INTO user_fortigate_access(user_id,connection_id,assigned_at) VALUES(?,?,UTC_TIMESTAMP(6))',[$id,$deviceId]);
                execute('DELETE p FROM user_fortigate_preferences p LEFT JOIN user_fortigate_access a ON a.user_id=p.user_id AND a.connection_id=p.connection_id WHERE p.user_id=? AND a.user_id IS NULL',[$id]);
                if($before!==$ids)audit('user_fortigate_access','user_id='.$id.';before='.implode(',',$before).';after='.implode(',',$ids));
            }
            audit('save_user','user_id='.$id);
        }elseif($route==='reset_user_password'){
            $id=management_int($data,'id');$old=query('SELECT id,revision FROM users WHERE id=? FOR UPDATE',[$id])[0]??null;if(!$old)throw new ManagementError('Kullanıcı bulunamadı.',404);
            if(management_int($data,'revision')!==(int)$old['revision'])throw new ManagementError('Hesap başka bir oturumda değişti. Listeyi yenileyin.',409);
            $hash=management_password($data);execute('UPDATE users SET password_hash=?,must_change=1,session_version=session_version+1,revision=revision+1,updated_at=UTC_TIMESTAMP() WHERE id=?',[$hash,$id]);audit('reset_user_password','user_id='.$id);
        }else throw new ManagementError('Bilinmeyen ayar işlemi.',404);
        $pdo->commit();return ['saved'=>true,'id'=>$id];
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();if($e instanceof PDOException&&$e->getCode()==='23000')throw new ManagementError('Aynı kullanıcı adı veya cihaz kimliği zaten kayıtlı.',409);throw $e;}
}
