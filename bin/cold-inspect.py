#!/usr/bin/python3
"""Verify, restore or query signed detailed snapshots without production SQL."""
import argparse
import json
from pathlib import Path
import tempfile
from cold_format import ColdError,restore_bundle,verify_bundle,query_events,typed_row

class JSONParser(argparse.ArgumentParser):
 def error(self,_message):
  print('{"verified":false,"error":"arguments_invalid"}');raise SystemExit(2)
 def print_help(self,file=None):
  print(json.dumps({'help':self.format_help()},ensure_ascii=False))

def main():
 parser=JSONParser(description=__doc__)
 sub=parser.add_subparsers(dest='command',required=True)
 for name in ('verify','restore','query'):
  p=sub.add_parser(name);p.add_argument('bundle',type=Path);p.add_argument('--public-key',type=Path,required=True)
  if name=='restore':p.add_argument('output_dir',type=Path)
  if name=='query':
   p.add_argument('--serial',required=True);p.add_argument('--vdom',required=True);p.add_argument('--source');p.add_argument('--q');p.add_argument('--limit',type=int,default=100)
 args=parser.parse_args()
 try:
  if args.command=='verify':result=verify_bundle(args.bundle,args.public_key)
  elif args.command=='restore':
   target=restore_bundle(args.bundle,args.output_dir,args.public_key)
   result={'verified':True,'sqlite_path':str(target),'production_database_touched':False}
  else:
   # Never query an arbitrary caller-supplied SQLite database. Verify the signed
   # bundle into a private temporary location on every CLI query instead.
   with tempfile.TemporaryDirectory(prefix='fls-cold-query-') as folder:
    target=restore_bundle(args.bundle,Path(folder)/'verified',args.public_key)
    rows=query_events(target,args.serial,args.vdom,args.source,args.q,args.limit)
    result={'verified':True,'row_encoding':'fls-typed-v1','rows':[typed_row(row) for row in rows],'count':len(rows),'production_database_touched':False}
  print(json.dumps(result,ensure_ascii=False,separators=(',',':'),allow_nan=False));return 0
 except (ColdError,OSError,ValueError) as exc:
  print(json.dumps({'verified':False,'error':str(exc) if isinstance(exc,ColdError) else 'snapshot_unavailable'},separators=(',',':')));return 2

if __name__=='__main__':raise SystemExit(main())
