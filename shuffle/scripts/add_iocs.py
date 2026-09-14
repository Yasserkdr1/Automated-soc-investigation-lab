# Shuffle step: add normalized IOC targets to the created IRIS case.
import json
import urllib.request
import urllib.error
import ssl
FINAL_DECISION_RAW = '$final_decision.message'
IRIS_CREATE_CASE_RAW = '$iris_create_case'
IRIS_URL = '$iris_url'
IRIS_API_KEY = '$iris_api_key'
VERIFY_TLS = False
IOC_TLP_ID = 2
IOC_TYPE_IDS = {'domain': 20, 'ip': 76, 'sha256': 113, 'url': 141}

def jload(value):
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or value.startswith('$'):
        return None
    try:
        return json.loads(value)
    except Exception:
        return None

def sslctx():
    if VERIFY_TLS:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def extract_case_id(raw):
    data = jload(raw)
    if not isinstance(data, dict):
        return None
    body = data.get('body')
    if isinstance(body, str):
        body = jload(body)
    if not isinstance(body, dict):
        return None
    case_data = body.get('data')
    if not isinstance(case_data, dict):
        return None
    return case_data.get('case_id')

def get_ioc_targets(raw):
    data = jload(raw)
    if not isinstance(data, dict):
        return []
    iris = data.get('iris') or {}
    targets = iris.get('ioc_targets') or []
    if not isinstance(targets, list):
        return []
    return targets

def add_ioc(case_id, ioc_type, value):
    type_id = IOC_TYPE_IDS.get(str(ioc_type).lower())
    if type_id is None:
        return {'success': False, 'type': ioc_type, 'value': value, 'reason': 'unsupported_ioc_type'}
    if not value:
        return {'success': False, 'type': ioc_type, 'value': value, 'reason': 'empty_ioc_value'}
    url = IRIS_URL.rstrip('/') + '/case/ioc/add?cid=' + str(case_id)
    payload = {'ioc_type_id': type_id, 'ioc_tlp_id': IOC_TLP_ID, 'ioc_value': value, 'ioc_description': 'IOC extracted automatically from Wazuh and Shuffle.', 'ioc_tags': 'wazuh,shuffle,automated', 'custom_attributes': {}}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method='POST', headers={'Authorization': 'Bearer ' + IRIS_API_KEY, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, context=sslctx(), timeout=15) as response:
            body = json.loads(response.read().decode())
            return {'success': True, 'type': ioc_type, 'type_id': type_id, 'value': value, 'http_status': response.status, 'iris_response': body}
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', errors='replace')
        try:
            detail = json.loads(detail)
        except Exception:
            pass
        return {'success': False, 'type': ioc_type, 'type_id': type_id, 'value': value, 'http_status': e.code, 'iris_response': detail}
    except Exception as e:
        return {'success': False, 'type': ioc_type, 'type_id': type_id, 'value': value, 'reason': type(e).__name__, 'detail': str(e)}
try:
    case_id = extract_case_id(IRIS_CREATE_CASE_RAW)
    if not case_id:
        raise ValueError('Unable to extract IRIS case_id')
    targets = get_ioc_targets(FINAL_DECISION_RAW)
    if not targets:
        print(json.dumps({'status': 'skipped', 'reason': 'no_iocs', 'case_id': case_id, 'added': 0, 'failed': 0, 'results': []}, ensure_ascii=False))
    else:
        seen = set()
        unique_targets = []
        for item in targets:
            if not isinstance(item, dict):
                continue
            ioc_type = item.get('type')
            value = item.get('value')
            key = (str(ioc_type).lower(), str(value))
            if key in seen:
                continue
            seen.add(key)
            unique_targets.append({'type': ioc_type, 'value': value})
        results = []
        for item in unique_targets:
            result = add_ioc(case_id, item.get('type'), item.get('value'))
            results.append(result)
        added = sum((1 for r in results if r.get('success') is True))
        failed = sum((1 for r in results if r.get('success') is not True))
        print(json.dumps({'status': 'ok' if failed == 0 else 'partial', 'case_id': case_id, 'requested': len(unique_targets), 'added': added, 'failed': failed, 'results': results}, ensure_ascii=False))
except Exception as e:
    print(json.dumps({'status': 'error', 'reason': type(e).__name__, 'detail': str(e)}, ensure_ascii=False))
