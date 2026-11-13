#!/usr/bin/python3
"""Idempotent derived memberships; never modifies original events or raw files."""
import json
from importer import connect,security_group_key,SECURITY_GROUP_MODULES

def main():
    db=connect();last=0;added=0
    try:
        while True:
            with db.cursor() as c:
                modules=','.join(['%s']*len(SECURITY_GROUP_MODULES))
                c.execute("SELECT e.id,e.fields FROM events e LEFT JOIN security_event_groups g ON g.event_id=e.id WHERE e.id>%s AND e.subtype IN ("+modules+") AND e.outcome='security_block' AND g.event_id IS NULL ORDER BY e.id LIMIT 1500",(last,*SECURITY_GROUP_MODULES))
                rows=c.fetchall()
                if not rows:break
                values=[(eid,*security_group_key(json.loads(fields),eid)) for eid,fields in rows]
                c.executemany('INSERT IGNORE INTO security_event_groups(event_id,group_key,key_complete,identity_json) VALUES(%s,%s,%s,%s)',values)
                added+=c.rowcount;last=rows[-1][0]
            db.commit()
        print(json.dumps({'memberships_added':added}))
    finally:db.close()

if __name__=='__main__':main()
