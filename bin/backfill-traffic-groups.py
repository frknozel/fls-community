#!/usr/bin/python3
"""Bounded PK windows create compact derived memberships without rewriting events."""
import argparse,json,time
from pathlib import Path
from importer import connect,insert_traffic_memberships
import pymysql

def main():
    p=argparse.ArgumentParser();p.add_argument('--progress-file');args=p.parse_args();db=connect();added=0;started=time.monotonic()
    try:
        with db.cursor() as c:
            c.execute('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED')
            c.execute('SELECT id FROM events ORDER BY id DESC LIMIT 1');last=c.fetchone();maximum=last[0] if last else 0
        db.commit()
        for start in range(0,maximum,5000):
            end=min(start+5000,maximum)
            for attempt in range(5):
                try:
                    with db.cursor() as c:
                        c.execute("SELECT e.id,e.event_at,e.profile,e.fields FROM events e FORCE INDEX(PRIMARY) LEFT JOIN traffic_event_groups g ON g.event_id=e.id WHERE e.id>%s AND e.id<=%s AND e.outcome IN ('policy_deny','local_deny') AND g.event_id IS NULL ORDER BY e.id",(start,end))
                        rows=c.fetchall();n=insert_traffic_memberships(c,rows,ignore_existing=True)
                    db.commit();added+=n;break
                except pymysql.OperationalError as error:
                    db.rollback()
                    if error.args[0] not in (1020,1205,1213) or attempt==4:raise
                    time.sleep(.05*(attempt+1))
            if args.progress_file:
                path=Path(args.progress_file);tmp=path.with_suffix('.new');tmp.write_text(json.dumps({'through_id':end,'maximum_id':maximum,'memberships_added':added,'seconds':round(time.monotonic()-started,1)}));tmp.replace(path)
        print(json.dumps({'memberships_added':added,'through_id':maximum,'seconds':round(time.monotonic()-started,1)}))
    finally:db.close()

if __name__=='__main__':main()
