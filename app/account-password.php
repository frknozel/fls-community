<?php
declare(strict_types=1);
/** The version/hash predicate is a compare-and-swap against a concurrent admin reset. */
function account_change_password(int $uid,int $version,mixed $current,mixed $new,mixed $confirm): bool {
    if(!is_string($current)||!is_string($new)||!is_string($confirm)||strlen($current)>1024||!mb_check_encoding($new,'UTF-8'))throw new InvalidArgumentException('Parola alanları geçersiz.');
    $user=query('SELECT password_hash,session_version,enabled FROM users WHERE id=?',[$uid])[0]??null;
    if(!$user||!(int)$user['enabled']||(int)$user['session_version']!==$version)return false;
    if(!password_verify($current,$user['password_hash']))throw new InvalidArgumentException('Mevcut parola hatalı.');
    if(mb_strlen($new)<14||strlen($new)>256)throw new InvalidArgumentException('Yeni parola 14–256 karakter olmalı.');
    if($new!==$confirm)throw new InvalidArgumentException('Yeni parolalar eşleşmiyor.');
    if(hash_equals($current,$new))throw new InvalidArgumentException('Yeni parola önceki paroladan farklı olmalı.');
    $hash=password_hash($new,PASSWORD_ARGON2ID);
    $pdo=db();$pdo->beginTransaction();
    try{
        $s=$pdo->prepare('UPDATE users SET password_hash=?,must_change=0,session_version=session_version+1,revision=revision+1,updated_at=UTC_TIMESTAMP() WHERE id=? AND enabled=1 AND session_version=? AND BINARY password_hash=BINARY ?');
        $s->execute([$hash,$uid,$version,$user['password_hash']]);
        if($s->rowCount()!==1){$pdo->rollBack();return false;}
        audit('password_changed');$pdo->commit();return true;
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
