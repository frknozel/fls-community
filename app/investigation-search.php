<?php
declare(strict_types=1);
require_once __DIR__.'/source-summary.php';
final class InvestigationSearchUnavailable extends RuntimeException {}
function investigation_search_term(): array {
 $query=$_GET['lookup']??'';
 if(!is_string($query)||!mb_check_encoding($query,'UTF-8')||mb_strlen(trim($query))<2||mb_strlen(trim($query))>120||preg_match('/[\x00-\x1f\x7f]/u',$query))throw new InvalidArgumentException('IP, cihaz adı veya alan adı için 2–120 karakter girin.');
 $query=trim($query);$term=$query;
 if(preg_match('~^https?://~i',$term)){$host=parse_url($term,PHP_URL_HOST);if(!is_string($host)||$host==='')throw new InvalidArgumentException('Geçerli bir hedef adresi girin.');$term=trim($host,'[]');}
 $term=mb_strtolower(rtrim($term,'.'));if(mb_strlen($term)<2)throw new InvalidArgumentException('Aranacak geçerli bir IP, cihaz adı veya alan adı girin.');$ip=filter_var($term,FILTER_VALIDATE_IP)!==false;
 if($ip)$term=inet_ntop(inet_pton($term));
 return [$query,$term,$ip];
}
function investigation_search_matches(string $value,string $term,bool $ip): bool {
 return $ip?(@inet_pton($value)!==false&&inet_pton($value)===inet_pton($term)):mb_stripos($value,$term)!==false;
}
function investigation_search(): array {
 [$query,$term,$ip]=investigation_search_term();$kind=$_GET['lookup_scope']??'all';$outcomes=['all'=>'all_blocks','security'=>'security_block','policy'=>'policy_deny','local'=>'local_deny'];
 if(!is_string($kind)||!isset($outcomes[$kind]))throw new InvalidArgumentException('Arama engel kapsamı geçersiz.');
 [$from,$to]=scope();$watermark=archive_watermark();
 if($watermark===null)throw new InvestigationSearchUnavailable('Özet indeksi arama için henüz hazır değil. Biraz sonra yeniden deneyin veya kayıtlarda metin araması kullanın.');
 $names=[];$namedMatches=[];
 foreach(query('SELECT ip,name,observed_at FROM '.fg_scoped_table('device_sources').' names') as $row){$names[$row['ip']]=$row;if(!$ip&&investigation_search_matches($row['name'],$term,false))$namedMatches[]=$row['ip'];}
 $pattern='%'.strtr($term,['='=>'==','%'=>'=%','_'=>'=_']).'%';
 // Only the small dimension dictionary and the bounded unindexed tail are
 // searched. Counts retain the same whole-hour/partial-hour snapshot as reports.
 $restrict=function(string $alias)use($term,$ip,$pattern,$namedMatches):array {
  $target="JSON_UNQUOTE(JSON_EXTRACT($alias.target_json,'$.value'))";
  if($ip)return ["(INET6_ATON($alias.srcip)=INET6_ATON(?) OR INET6_ATON($target)=INET6_ATON(?))",[$term,$term]];
  $sql="($alias.srcip LIKE ? ESCAPE '=' OR LOWER($target) LIKE ? ESCAPE '='";$args=[$pattern,$pattern];
  if($namedMatches){$sql.=" OR $alias.srcip IN (".implode(',',array_fill(0,count($namedMatches),'?')).')';array_push($args,...$namedMatches);}
  return [$sql.')',$args];
 };
 [$sql,$args]=archive_summary_query(['outcome'=>$outcomes[$kind]],$from,$to,$watermark,false,false,$restrict);
 $spool=new ReportRankingSpool();$sources=new ReportRanking($spool);$targets=new ReportRanking($spool);$matchedRecords=0;$pdo=db();$statement=null;$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,false);
 $add=function(ReportRanking $rows,string $key,array $identity,array $row):void {
  $rows->add($key,$identity,(int)$row['n'],$row['first_event_at'],$row['last_event_at']);
 };
 try {
  $statement=$pdo->prepare($sql);$statement->execute($args);
  while($row=$statement->fetch()){
   $source=$row['srcip'];$name=$names[$source]['name']??'';
   $sourceMatch=$source!==''&&(investigation_search_matches($source,$term,$ip)||!$ip&&investigation_search_matches($name,$term,false));
   if($sourceMatch)$add($sources,$source,['ip'=>$source,'name'=>$name,'name_observed_at'=>$names[$source]['observed_at']??null],$row);
   $target=json_decode($row['target_json'],true,512,JSON_THROW_ON_ERROR);
   $targetMatch=($target['value']??'')!==''&&investigation_search_matches($target['value'],$term,$ip);
   if($targetMatch){$key=hash('sha256',$row['target_json']);$add($targets,$key,['target'=>$target+['key'=>$key,'label'=>$target['value']]],$row);}
   if($sourceMatch||$targetMatch)$matchedRecords+=(int)$row['n'];
  }
 }finally{if($statement)$statement->closeCursor();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,true);}
 $sourceResult=$sources->finish(8);$targetResult=$targets->finish(8);
 $withoutKey=function(array $row):array{unset($row['key']);return $row;};
 return ['query'=>$query,'normalized_query'=>$term,'scope'=>['from_utc'=>$from,'to_utc'=>$to,'kind'=>$kind,'device_id'=>(int)fg_selected_device()['id']],'matched_records'=>$matchedRecords,'source_total'=>$sourceResult['distinct'],'target_total'=>$targetResult['distinct'],'sources'=>array_map($withoutKey,$sourceResult['rows']),'targets'=>array_map($withoutKey,$targetResult['rows']),'counting'=>'original_block_records','generated_at'=>gmdate('c')];
}
