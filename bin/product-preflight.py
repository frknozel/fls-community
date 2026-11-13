#!/usr/bin/python3
"""Read-only deployment preflight; no disk partitioning, package upgrade, service stop or install."""
import argparse,json,os,platform,shutil,subprocess
from pathlib import Path
from product_config import load
def assess(config,existing,tools,free_bytes,ram_bytes,cpu_count):
    errors=[];warnings=[]
    if existing:errors.append('existing_installation_requires_upgrade_not_bootstrap')
    for name in ['php','nginx','mariadb','openssl','setfacl','systemctl']:
        if not tools.get(name):errors.append('missing_tool_'+name)
    if ram_bytes<8*1024**3:errors.append('ram_below_8_gib')
    if cpu_count<4:warnings.append('cpu_below_benchmark_starting_profile')
    if free_bytes<40*1024**3:errors.append('data_free_below_40_gib')
    return {'schema':1,'installation_id':config['installation_id'],'ready_for_bootstrap':not errors,'errors':errors,'warnings':warnings,'capacity_certified':False,'configured_retention_years':[2,3,4],'fast_window_days':[45,70,90],'retention_defaults':{'retention_years':2,'fast_days':45},'destructive_actions':False,'commercial_image_ready':False,'remaining':['first_boot_web_enrollment','signed_upgrade_and_schema_rollback','hypervisor_image_build_and_boot_test','third_party_corresponding_source_and_license_review']}
def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();d=load(a.config);mem={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc/meminfo').read_text().splitlines()};folder=Path(d['data_path']);folder=folder if folder.exists() else folder.parent
    existing=Path('/etc/fls/app.json').exists() or Path('/etc/fls/private/archive-ed25519.pem').exists()
    result=assess(d,existing,{k:shutil.which(k) is not None for k in ['php','nginx','mariadb','openssl','setfacl','systemctl']},shutil.disk_usage(folder).free,int(mem['MemTotal'].split()[0])*1024,os.cpu_count() or 1)
    result['platform']=platform.machine();print(json.dumps(result,indent=2));raise SystemExit(0 if result['ready_for_bootstrap'] else 2)
if __name__=='__main__':main()
