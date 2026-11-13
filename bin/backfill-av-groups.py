#!/usr/bin/python3
"""Create derived memberships only; preserve original events and notes."""
import json
from importer import connect,antivirus_group_key
db=connect()
with db.cursor() as c:
    c.execute("SELECT e.id,e.srcip,e.fields FROM events e LEFT JOIN av_event_groups g ON g.event_id=e.id WHERE e.subtype='virus' AND g.event_id IS NULL")
    rows=c.fetchall()
    values=[(eid,*antivirus_group_key(ip,json.loads(fields),eid)) for eid,ip,fields in rows]
    if values:c.executemany('INSERT IGNORE INTO av_event_groups(event_id,group_key,key_complete) VALUES(%s,%s,%s)',values)
db.commit();db.close();print(json.dumps({'memberships_added':len(values)}))
