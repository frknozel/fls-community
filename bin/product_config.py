#!/usr/bin/python3
"""Portable appliance identity/config rendering. Never invokes shell or changes host networking."""
import argparse,ipaddress,json,os,re,stat,tempfile,uuid
from pathlib import Path
FIELDS={'schema','installation_id','hostname','bind_ip','collector_ip','collector_port','timezone','management_network','storage_label','data_path'}
def validate(raw):
    if not isinstance(raw,dict) or set(raw)-FIELDS or type(raw.get('schema')) is not int or raw['schema']!=1:raise ValueError('instance_schema')
    d=dict(raw)
    try:identifier=uuid.UUID(d.get('installation_id',''))
    except (ValueError,TypeError,AttributeError):raise ValueError('installation_id') from None
    if identifier.version!=4 or str(identifier)!=d['installation_id']:raise ValueError('installation_id')
    host=d.get('hostname','')
    if not isinstance(host,str) or len(host)>253 or not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?',host) or any(not part or len(part)>63 or part.startswith('-') or part.endswith('-') for part in host.split('.')):raise ValueError('hostname')
    for key in ['bind_ip','collector_ip']:
        ip=ipaddress.ip_address(d.get(key,''))
        if ip.version!=4 or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved or int(ip)<0x01000000 or int(ip)>=0xe0000000:raise ValueError(key)
        d[key]=str(ip)
    if type(d.get('collector_port')) is not int or d['collector_port']!=5514:raise ValueError('collector_port')
    # UTC is the persistence format. First product target uses one consistent Turkish UI calendar.
    if d.get('timezone')!='Europe/Istanbul':raise ValueError('timezone')
    network=ipaddress.ip_network(d.get('management_network',''),strict=True)
    if network.version!=4 or network.prefixlen<8 or ipaddress.ip_address(d['bind_ip']) not in network:raise ValueError('management_network')
    d['management_network']=str(network)
    if d.get('data_path')!='/srv/fortigate':raise ValueError('data_path')
    label=d.get('storage_label','')
    if not isinstance(label,str) or not 1<=len(label)<=80 or any(ord(c)<32 or ord(c)==127 for c in label):raise ValueError('storage_label')
    return d

def load(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>16384:raise ValueError('instance_file')
        return validate(json.loads(f.read(16385)))

def render(d,collector_template):
    collector=collector_template.replace('Address="192.0.2.2" Port="5514"','Address="'+d['collector_ip']+'" Port="5514"')
    if '192.0.2.2' in collector:raise ValueError('collector_template')
    nginx='''# Generated configuration. Install only on a new appliance after preflight.
server {
 listen BIND:443 ssl;
 server_name HOST;
 ssl_certificate /etc/fls/tls/server.crt;
 ssl_certificate_key /etc/fls/tls/server.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 root /var/www/fls/public;
 index index.php;
 allow NETWORK;
 deny all;
 client_max_body_size 64k;
 add_header X-Content-Type-Options nosniff always;
 location / { try_files $uri $uri/ =404; }
 location ~ \\.php$ {
  try_files $uri =404;
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  fastcgi_pass unix:/run/php/fls.sock;
 }
 location ~ /\\. { deny all; }
}
'''.replace('BIND',d['bind_ip']).replace('HOST',d['hostname']).replace('NETWORK',d['management_network'])
    return {'instance.json':json.dumps(d,indent=2,ensure_ascii=False)+'\n','fls-nginx.conf':nginx,'fortigate-rsyslog.conf':collector}

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--output',required=True);a=p.parse_args();d=load(a.config);target=Path(a.output)
    if target.exists() and any(target.iterdir()):raise SystemExit('Output directory must be empty')
    target.mkdir(parents=True,exist_ok=True,mode=0o700)
    for name,value in render(d,(Path(__file__).resolve().parents[1]/'deploy/fortigate-rsyslog.conf').read_text()).items():
        path=target/name
        with path.open('x') as f:f.write(value);f.flush();os.fsync(f.fileno())
        path.chmod(0o600)
    print(json.dumps({'rendered':3,'installation_id':d['installation_id'],'applied_to_host':False}))
if __name__=='__main__':main()
