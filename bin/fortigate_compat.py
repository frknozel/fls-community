"""Strict public inventory and conservative per-component compatibility facts.

No serial aliases, wildcard VDOMs or implicit HA trust is introduced here.
"""
import re

OPTIONAL = frozenset({'performance','ipsec','ssl_vpn','sdwan_health','sdwan_members','ha','sdwan_settings','profile_groups','profiles_virus','profiles_webfilter','profiles_app-ctrl','profiles_dns','profiles_ips','profiles_ssl','url_filters','categories'})
STATES = frozenset({'available','disabled','unsupported','permission_denied','authentication_failed','temporary_error','unknown'})

def safe_string(value, limit=128):
    if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 or ord(c)==127 for c in value):return None
    return value

def integer(value, maximum=1000000):
    return value if isinstance(value,int) and not isinstance(value,bool) and 0<=value<=maximum else None

def inventory(envelope):
    value=envelope.get('results')
    if not isinstance(value,dict):raise ValueError('inventory_schema')
    result={k:safe_string(value.get(k)) for k in ['model_name','model_number','model','hostname']}
    version=safe_string(envelope.get('version'),32)
    result['version']=version if version and re.fullmatch(r'v?\d{1,2}\.\d{1,2}\.\d{1,3}(?:[-.][A-Za-z0-9]+)?',version) else None
    result['build']=integer(envelope.get('build'))
    if not result['model'] and not result['model_number']:raise ValueError('inventory_schema')
    result['serial']=safe_string(envelope.get('serial'),40)
    result['vdom']=safe_string(envelope.get('vdom'),64)
    result['log_disk_status']=value.get('log_disk_status') if value.get('log_disk_status') in ('available','not_available','not available','disabled','none') else None
    # Missing fields remain unknown; single-device connectivity does not prove standalone HA.
    result['ha_mode']=value.get('ha_mode') if value.get('ha_mode') in ('standalone','a-p','a-a') else None
    result['ha_role']=value.get('ha_role') if value.get('ha_role') in ('primary','secondary','master','slave') else None
    return result

def availability(key,error,identity_verified=False,disabled=False):
    if error is None:return {'state':'disabled' if disabled else 'available','reason':'configured_disabled' if disabled else 'api_success'}
    if error=='http_401':state='authentication_failed'
    elif error=='http_403':state='permission_denied'
    elif key in OPTIONAL and identity_verified and error in ('http_404','http_405','http_501'):state='unsupported'
    elif error in ('connection_or_json','poll_budget','http_408','http_429','http_500','http_502','http_503','http_504'):state='temporary_error'
    else:state='unknown'
    return {'state':state,'reason':'endpoint_absent' if state=='unsupported' else error}
