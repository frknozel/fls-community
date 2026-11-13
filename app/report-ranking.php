<?php
declare(strict_types=1);

/** Exact external merge for reports; neither unique-key count nor labels fill RAM. */
final class ReportRankingLimit extends InvalidArgumentException {
    public function __construct(){parent::__construct('Bu aralıkta rapor boyutu güvenli işlem sınırını aşıyor. Tarih aralığını veya kaynak / hedef / policy filtresini daraltın.');}
}
final class ReportRankingSpool {
    private ?string $directory=null;
    private array $files=[];
    private int $bytes=0,$written=0,$lastChecked=0,$sequence=0;
    public function __construct(private int $maximumBytes=134217728,private int $maximumWritten=536870912,private int $reserveBytes=67108864){}
    public function create(): array {
        if(count($this->files)>=128)throw new ReportRankingLimit();
        if($this->directory===null){
            $parent=realpath(sys_get_temp_dir());if($parent===false)throw new ReportRankingLimit();
            $path=$parent.'/fls-report-'.bin2hex(random_bytes(16));
            if(!@mkdir($path,0700))throw new ReportRankingLimit();
            $this->directory=$path;
            $weak=WeakReference::create($this);
            register_shutdown_function(static function()use($weak):void{$spool=$weak->get();if($spool!==null)$spool->close();});
        }
        $this->checkSpace();$path=$this->directory.'/'.(++$this->sequence).'.jsonl';
        $handle=@fopen($path,'x+b');if($handle===false)throw new ReportRankingLimit();
        $this->files[$path]=0;
        if(!@chmod($path,0600)){fclose($handle);throw new ReportRankingLimit();}
        return [$path,$handle];
    }
    private function checkSpace(): void {
        $free=@disk_free_space($this->directory??sys_get_temp_dir());
        if($free===false||$free<$this->reserveBytes)throw new ReportRankingLimit();
        $this->lastChecked=$this->written;
    }
    public function write(string $path,mixed $handle,array $entry): void {
        $line=json_encode($entry,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)."\n";$size=strlen($line);
        if($size>131072||$size>$this->maximumBytes-$this->bytes||$size>$this->maximumWritten-$this->written)throw new ReportRankingLimit();
        if($this->written-$this->lastChecked>=1048576)$this->checkSpace();
        $this->bytes+=$size;$this->written+=$size;$this->files[$path]+=$size;
        if(@fwrite($handle,$line)!==$size)throw new ReportRankingLimit();
    }
    public function remove(string $path): void {
        if(!isset($this->files[$path]))throw new LogicException('Unknown report spool');
        if(!@unlink($path))throw new ReportRankingLimit();
        $this->bytes-=$this->files[$path];unset($this->files[$path]);
    }
    public function close(): void {
        foreach($this->files as $path=>$size)@unlink($path);
        $this->files=[];$this->bytes=0;
        if($this->directory!==null){@rmdir($this->directory);$this->directory=null;}
    }
    public function __destruct(){$this->close();}
}
final class ReportRanking {
    private array $entries=[],$runs=[];
    private int $sequence=0,$memory=0;
    private bool $finished=false;
    public function __construct(private ReportRankingSpool $spool,private bool $dates=true,private int $maximumKeys=1024,private int $maximumMemory=1048576){}
    private static function size(mixed $value,int $depth=0): int {
        if($depth>8)throw new ReportRankingLimit();
        if(is_string($value)){if(strlen($value)>32768)throw new ReportRankingLimit();return strlen($value)+32;}
        if(is_array($value)){
            if(count($value)>64)throw new ReportRankingLimit();$size=64;
            foreach($value as $key=>$item){$size+=self::size((string)$key,$depth+1)+self::size($item,$depth+1)+64;if($size>65536)throw new ReportRankingLimit();}
            return $size;
        }
        if($value===null||is_int($value)||is_float($value)||is_bool($value))return 32;
        throw new ReportRankingLimit();
    }
    public function add(string $key,array $facts,int $records,?string $first=null,?string $last=null): void {
        if($this->finished)throw new LogicException('Finished report ranking');
        if(strlen($key)>4096||$records<0||($first!==null&&strlen($first)>64)||($last!==null&&strlen($last)>64)
                ||array_intersect_key($facts,array_flip(['key','records','first_event_at','last_event_at'])))throw new ReportRankingLimit();
        $size=self::size($facts)+strlen($key)*2+512;$slot='k'.$key;$sequence=++$this->sequence;
        if(!isset($this->entries[$slot])){
            if($this->entries&&(count($this->entries)>=$this->maximumKeys||$this->memory+$size>$this->maximumMemory))$this->flush();
            $this->entries[$slot]=['key'=>$key,'facts'=>$facts,'records'=>$records,'first'=>$first,'last'=>$last,'sequence'=>$sequence];$this->memory+=$size;
        }else $this->entries[$slot]=self::combine($this->entries[$slot],['key'=>$key,'facts'=>$facts,'records'=>$records,'first'=>$first,'last'=>$last,'sequence'=>$sequence]);
    }
    private static function combine(array $a,array $b): array {
        if($b['records']>PHP_INT_MAX-$a['records'])throw new ReportRankingLimit();
        $result=$a['sequence']<=$b['sequence']?$a:$b;$result['records']=$a['records']+$b['records'];
        $result['first']=$a['first']===null?$b['first']:($b['first']===null?$a['first']:min($a['first'],$b['first']));
        $result['last']=$a['last']===null?$b['last']:($b['last']===null?$a['last']:max($a['last'],$b['last']));
        return $result;
    }
    private function flush(): void {
        if(!$this->entries)return;
        [$path,$handle]=$this->spool->create();
        try{
            uasort($this->entries,fn($a,$b)=>strcmp($a['key'],$b['key']));
            foreach($this->entries as $entry)$this->spool->write($path,$handle,$entry);
            if(!@fflush($handle))throw new ReportRankingLimit();
        }finally{fclose($handle);}
        $this->entries=[];$this->memory=0;$this->runs[]=['path'=>$path,'level'=>0];
        // Leveled compaction: <=15 runs per level, at most 17 open descriptors.
        while(count($this->runs)>=16){
            $tail=array_slice($this->runs,-16);$level=$tail[0]['level'];
            if(count(array_filter($tail,fn($run)=>$run['level']===$level))!==16)break;
            $merged=$this->merge($tail,$level+1);array_splice($this->runs,-16,16,[$merged]);
        }
    }
    private static function read(mixed $handle): ?array {
        $line=fgets($handle,131073);
        if($line===false){if(!feof($handle))throw new ReportRankingLimit();return null;}
        if(!str_ends_with($line,"\n"))throw new ReportRankingLimit();
        $entry=json_decode($line,true,32,JSON_THROW_ON_ERROR);
        if(!is_array($entry))throw new ReportRankingLimit();return $entry;
    }
    private function sorted(array $runs): Generator {
        $handles=[];$heads=[];
        try{
            foreach($runs as $i=>$run){$handle=@fopen($run['path'],'rb');if($handle===false)throw new ReportRankingLimit();$handles[$i]=$handle;$heads[$i]=self::read($handle);}
            $current=null;
            while(true){
                $next=null;foreach($heads as $i=>$entry)if($entry!==null&&($next===null||strcmp($entry['key'],$heads[$next]['key'])<0))$next=$i;
                if($next===null)break;$entry=$heads[$next];$heads[$next]=self::read($handles[$next]);
                if($current!==null&&$current['key']!==$entry['key']){yield $current;$current=null;}
                $current=$current===null?$entry:self::combine($current,$entry);
            }
            if($current!==null)yield $current;
        }finally{foreach($handles as $handle)fclose($handle);}
    }
    private function merge(array $runs,int $level): array {
        if($level>8)throw new ReportRankingLimit();
        [$path,$handle]=$this->spool->create();
        try{foreach($this->sorted($runs) as $entry)$this->spool->write($path,$handle,$entry);if(!@fflush($handle))throw new ReportRankingLimit();}
        finally{fclose($handle);}
        foreach($runs as $run)$this->spool->remove($run['path']);
        return ['path'=>$path,'level'=>$level];
    }
    public function finish(int $limit=10,?callable $each=null): array {
        if($this->finished||$limit<0||$limit>100)throw new LogicException('Invalid report ranking finish');$this->finished=true;
        if($this->runs){
            $this->flush();
            while(count($this->runs)>16){$chunk=array_splice($this->runs,0,16);$this->runs[]=$this->merge($chunk,max(array_column($chunk,'level'))+1);}
            $entries=$this->sorted($this->runs);
        }else $entries=$this->entries;
        $rows=[];$distinct=0;
        foreach($entries as $entry){
            $distinct++;$row=$entry['facts']+['key'=>$entry['key'],'records'=>$entry['records']];
            if($this->dates)$row+=['first_event_at'=>$entry['first'],'last_event_at'=>$entry['last']];
            if($each!==null)$each($row);
            if($limit){$rows[]=$row;usort($rows,fn($a,$b)=>($b['records']<=>$a['records'])?:strcmp($a['key'],$b['key']));if(count($rows)>$limit)array_pop($rows);}
        }
        foreach($this->runs as $run)$this->spool->remove($run['path']);$this->runs=[];$this->entries=[];$this->memory=0;
        return ['distinct'=>$distinct,'rows'=>$rows];
    }
}
