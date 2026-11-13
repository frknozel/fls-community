<?php
declare(strict_types=1);

/** A short-lived, administrator-only export prepared by a separate root worker. */
final class RecoveryDownloadError extends RuntimeException {
    public function __construct(public readonly int $status) { parent::__construct('Recovery download unavailable.'); }
}

function recovery_download_same_stat(array $left,array $right): bool {
    foreach(['dev','ino','mode','uid','gid','nlink','size','mtime','ctime'] as $key)
        if(!array_key_exists($key,$left)||!array_key_exists($key,$right)||$left[$key]!==$right[$key])return false;
    return true;
}

/** Every component must be a real directory. Only root may replace the export. */
function recovery_download_directory(string $directory): array {
    if($directory===''||$directory[0]!=='/'||str_contains($directory,"\0"))throw new RecoveryDownloadError(409);
    $group=function_exists('posix_getgrnam')?posix_getgrnam('fls-web'):false;
    if(!$group)throw new RecoveryDownloadError(503);
    $parts=explode('/',substr($directory,1));$path='';$last=count($parts)-1;$info=false;
    foreach($parts as $index=>$part){
        if($part===''||$part==='.'||$part==='..')throw new RecoveryDownloadError(409);
        $path.='/'.$part;clearstatcache(true,$path);$info=@lstat($path);
        if(!$info||($info['mode']&0170000)!==0040000||$info['uid']!==0)throw new RecoveryDownloadError(409);
        // A root-owned sticky ancestor (e.g. /tmp in the isolated test) cannot
        // have its existing root-owned child replaced by an unprivileged user.
        if(($info['mode']&0022)!==0&&($index===$last||($info['mode']&01000)===0))throw new RecoveryDownloadError(409);
    }
    if(!$info||($info['mode']&07777)!==0750||$info['gid']!==(int)$group['gid'])throw new RecoveryDownloadError(409);
    return $info;
}

/** Pin one root-owned regular file before reading it; never follow a symlink. */
function recovery_download_open(string $path,int $group,int $maximum,?int $expected=null) {
    clearstatcache(true,$path);$before=@lstat($path);
    if(!$before)throw new RecoveryDownloadError(404);
    if(($before['mode']&0170000)!==0100000||($before['mode']&07777)!==0640
        ||$before['uid']!==0||$before['gid']!==$group||$before['nlink']!==1
        ||$before['size']<1||$before['size']>$maximum||($expected!==null&&$before['size']!==$expected))throw new RecoveryDownloadError(409);
    $stream=@fopen($path,'rb');if(!$stream)throw new RecoveryDownloadError(409);
    $opened=@fstat($stream);clearstatcache(true,$path);$current=@lstat($path);
    if(!$opened||!$current||!recovery_download_same_stat($before,$opened)||!recovery_download_same_stat($opened,$current)){
        fclose($stream);throw new RecoveryDownloadError(409);
    }
    return $stream;
}

function recovery_download_metadata(string $directory,int $group): array {
    $stream=recovery_download_open($directory.'/current.json',$group,16384);
    try{
        $before=fstat($stream);$body=stream_get_contents($stream);$after=fstat($stream);
        if($body===false||!$before||!$after||strlen($body)!==$before['size']||!recovery_download_same_stat($before,$after))throw new RecoveryDownloadError(409);
        $metadata=json_decode($body,true,16,JSON_THROW_ON_ERROR);
    }catch(JsonException $error){throw new RecoveryDownloadError(409);}
    finally{fclose($stream);}
    if(!is_array($metadata)||($metadata['schema']??null)!=='fls-recovery-download-v1'
        ||!is_string($metadata['filename']??null)||!preg_match('/\Afls-system-\d{8}-\d{6}Z\.tar\.gz\z/D',$metadata['filename'])
        ||!is_int($metadata['bytes']??null)||$metadata['bytes']<1
        ||!is_string($metadata['sha256']??null)||!preg_match('/\A[a-f0-9]{64}\z/D',$metadata['sha256'])
        ||!is_string($metadata['expires_at']??null)||!preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\z/D',$metadata['expires_at'])
        ||(array_key_exists('report_filename',$metadata)&&$metadata['report_filename']!==$metadata['filename'].'.verification.json'))throw new RecoveryDownloadError(409);
    try{
        $expires=new DateTimeImmutable($metadata['expires_at']);$errors=DateTimeImmutable::getLastErrors();
        if($errors&&($errors['warning_count']||$errors['error_count']))throw new RecoveryDownloadError(409);
    }catch(Exception $error){throw new RecoveryDownloadError(409);}
    if($expires<=new DateTimeImmutable('now',new DateTimeZone('UTC')))throw new RecoveryDownloadError(410);
    $metadata['expires']=$expires;return $metadata;
}

function recovery_download_headers(string $name,string $type,int $bytes,string $sha256,string $archiveSha256): void {
    header('Content-Type: '.$type);header('Content-Disposition: attachment; filename="'.$name.'"');
    header('Content-Length: '.$bytes);header('Cache-Control: private, no-store, max-age=0');
    header('Pragma: no-cache');header('Expires: 0');header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');header('Accept-Ranges: none');header('X-Accel-Buffering: no');
    header('X-FLS-SHA256: '.$sha256);header('X-FLS-Archive-SHA256: '.$archiveSha256);
}

/**
 * Bootstrap/authentication runs in api.php first. The directory argument is for
 * trusted PHP callers and isolated tests only; it must never come from HTTP.
 */
function recovery_download(string $directory='/var/lib/fls-recovery-download'): never {
    $stream=null;
    header('Cache-Control: private, no-store, max-age=0');
    try{
        if(($_SERVER['REQUEST_METHOD']??'')!=='GET'){header('Allow: GET');throw new RecoveryDownloadError(405);}
        $uid=$_SESSION['uid']??null;$version=$_SESSION['session_version']??null;
        if((!is_int($uid)&&(!is_string($uid)||!ctype_digit($uid)))||(int)$uid<1)throw new RecoveryDownloadError(401);
        if(($_SESSION['role']??'')!=='admin')throw new RecoveryDownloadError(403);
        if((!is_int($version)&&(!is_string($version)||!ctype_digit($version)))||(int)$version<0)throw new RecoveryDownloadError(403);
        $actor=query('SELECT role,enabled,session_version,must_change FROM users WHERE id=?',[(int)$uid])[0]??null;
        if(!$actor||($actor['role']??null)!=='admin'||(int)($actor['enabled']??0)!==1
            ||(int)($actor['session_version']??-1)!==(int)$version||(int)($actor['must_change']??1)!==0)throw new RecoveryDownloadError(403);
        foreach($_GET as $key=>$value)if(!in_array($key,['route','part'],true)||!is_string($value))throw new RecoveryDownloadError(422);
        $part=$_GET['part']??'archive';if(!in_array($part,['archive','sha256','report'],true))throw new RecoveryDownloadError(422);
        $directoryInfo=recovery_download_directory($directory);
        $metadata=recovery_download_metadata($directory,$directoryInfo['gid']);
        if($part==='sha256'){
            $body=$metadata['sha256'].'  '.$metadata['filename']."\n";
            recovery_download_headers($metadata['filename'].'.sha256','text/plain; charset=utf-8',strlen($body),hash('sha256',$body),$metadata['sha256']);
            echo $body;exit;
        }
        if($part==='report'&&!isset($metadata['report_filename']))throw new RecoveryDownloadError(404);
        $name=$part==='archive'?$metadata['filename']:$metadata['report_filename'];
        $stream=recovery_download_open($directory.'/'.$name,$directoryInfo['gid'],$part==='archive'?$metadata['bytes']:4194304,$part==='archive'?$metadata['bytes']:null);
        // Authenticate before allowing an expensive read. Hash and send the same
        // pinned descriptor; completed root exports must never be edited in place.
        @set_time_limit(0);$before=fstat($stream);$hash=hash_init('sha256');$read=hash_update_stream($hash,$stream);$sha256=hash_final($hash);$after=fstat($stream);
        if(!$before||!$after||$read!==$before['size']||!recovery_download_same_stat($before,$after)
            ||($part==='archive'&&!hash_equals($metadata['sha256'],$sha256)))throw new RecoveryDownloadError(409);
        if($metadata['expires']<=new DateTimeImmutable('now',new DateTimeZone('UTC')))throw new RecoveryDownloadError(410);
        // Hashing can take time: recheck authorization immediately before release.
        $actor=query('SELECT role,enabled,session_version,must_change FROM users WHERE id=?',[(int)$uid])[0]??null;
        if(!$actor||($actor['role']??null)!=='admin'||(int)($actor['enabled']??0)!==1
            ||(int)($actor['session_version']??-1)!==(int)$version||(int)($actor['must_change']??1)!==0)throw new RecoveryDownloadError(403);
        if(!rewind($stream))throw new RecoveryDownloadError(409);
        recovery_download_headers($name,$part==='archive'?'application/gzip':'application/json; charset=utf-8',$before['size'],$sha256,$metadata['sha256']);
    }catch(RecoveryDownloadError $error){
        if(is_resource($stream))fclose($stream);
        json_response(['error'=>'Kurtarma dosyası şu anda indirilemiyor.'],$error->status);
    }catch(Throwable $error){
        if(is_resource($stream))fclose($stream);
        error_log('FLS recovery download failed: '.get_class($error));
        json_response(['error'=>'Kurtarma dosyası şu anda indirilemiyor.'],503);
    }
    // No JSON error may be appended after a binary response has started.
    if(@fpassthru($stream)===false)error_log('FLS recovery download stream interrupted.');
    fclose($stream);exit;
}
