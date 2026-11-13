<?php
declare(strict_types=1);
final class MailSearchUnavailable extends RuntimeException {}
function mail_search_projection(string $alias): string {
 $parts=[];foreach(['from'=>'sender','to'=>'recipient','filename'=>'filename','messageid'=>'message_id'] as $key=>$name)$parts[]="IF(JSON_TYPE(JSON_EXTRACT($alias.fields,'$.$key'))='STRING',JSON_UNQUOTE(JSON_EXTRACT($alias.fields,'$.$key')),'') $name";
 return implode(',',$parts);
}
function mail_search_like(string $alias,string $field,string $q): array {
 $cols=$field==='mail'?['sender','recipient','filename','message_id']:[$field];$terms=[];$args=[];$like='%'.strtr($q,['!'=>'!!','%'=>'!%','_'=>'!_']).'%';
 foreach($cols as $column){$terms[]="$alias.$column COLLATE utf8mb4_unicode_ci LIKE ? ESCAPE '!'";$args[]=$like;}
 return ['('.implode(' OR ',$terms).')',$args];
}
/** Return exact candidate IDs from sparse history, a bounded live tail and current recipient notes. */
function mail_search_candidates(?array $range=null): array {
 $field=mail_search_field();$q=mail_search_term();if($field===''||$q==='')throw new InvalidArgumentException('E-posta veya dosya araması seçin.');
 $state=query('SELECT * FROM mail_search_state WHERE id=1')[0]??null;
 if(!$state||(int)$state['version']!==1||!(int)$state['ready'])throw new MailSearchUnavailable('E-posta ve dosya arama indeksi hazırlanıyor. Biraz sonra yeniden deneyin.');
 $watermark=(int)$state['event_id'];
 // Read one extra ID rather than counting the entire outstanding import.
 $tail=query('SELECT id FROM events FORCE INDEX(PRIMARY) WHERE id>? ORDER BY id LIMIT 10001',[$watermark]);
 if(count($tail)>10000)throw new MailSearchUnavailable('Arama indeksi yeni kayıtlara yetişiyor. Eksiksiz sonuçlar için biraz sonra yeniden deneyin.');
 [$from,$to]=$range??scope();[$match,$args]=mail_search_like('m',$field,$q);
 $indexed='SELECT m.event_id FROM mail_search_events m FORCE INDEX(device_time) WHERE '.fg_event_scope('m').' AND m.event_at>=? AND m.event_at<? AND '.$match;
 $params=[$from,$to,...$args];
 $projection=mail_search_projection('e');[$match,$args]=mail_search_like('tail',$field,$q);
 $raw="SELECT e.id event_id,$projection FROM events e FORCE INDEX(PRIMARY) WHERE e.id>? AND ".fg_event_scope('e').' AND e.event_at>=? AND e.event_at<?';
 $parts=[$indexed,"SELECT tail.event_id FROM ($raw) tail WHERE $match"];$params=array_merge($params,[$watermark,$from,$to],$args);
 if(in_array($field,['mail','recipient'],true)){
  // Verified recipients are live account annotations, not FortiGate recipient claims.
  $parts[]='SELECT COALESCE(shared.event_id,n.event_id) event_id FROM event_notes n JOIN events origin ON origin.id=n.event_id LEFT JOIN av_event_groups original ON original.event_id=n.event_id LEFT JOIN av_event_groups shared ON shared.group_key=original.group_key WHERE '.fg_event_scope('origin')." AND n.confirmed_recipient COLLATE utf8mb4_unicode_ci LIKE ? ESCAPE '!'";
  $params[]='%'.strtr($q,['!'=>'!!','%'=>'!%','_'=>'!_']).'%';
 }
 return [implode(' UNION ',$parts),$params];
}
