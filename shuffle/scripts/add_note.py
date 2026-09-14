# Shuffle step: add the behavioral-analysis note to the IRIS case.
import json
import ssl
import urllib.request
import urllib.error
FINAL_RAW = '$final_decision.message'
CASE_RAW = '$iris_create_case'
IRIS_URL = '$iris_url'
IRIS_API_KEY = '$iris_api_key'
VERIFY_TLS = False

def jload(v):
    if isinstance(v, (dict, list)):
        return v
    if not isinstance(v, str):
        return None
    try:
        return json.loads(v)
    except:
        return None

def ssl_context():
    ctx = ssl.create_default_context()
    if not VERIFY_TLS:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def post(path, payload):
    url = IRIS_URL.rstrip('/') + path
    req = urllib.request.Request(url, method='POST', data=json.dumps(payload).encode('utf-8'), headers={'Authorization': 'Bearer ' + IRIS_API_KEY, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, context=ssl_context(), timeout=15) as response:
            raw = response.read().decode('utf-8')
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', errors='replace')
        raise RuntimeError(f'HTTP {e.code}: {raw}')

def get_case_id():
    x = jload(CASE_RAW)
    if not isinstance(x, dict):
        return None
    body = x.get('body', x)
    if isinstance(body, str):
        body = jload(body)
    if not isinstance(body, dict):
        return None
    data = body.get('data') or {}
    return data.get('case_id')

def get_note_data():
    x = jload(FINAL_RAW)
    if not isinstance(x, dict):
        return (None, None)
    iris = x.get('iris') or {}
    return (iris.get('llm_note_title'), iris.get('llm_note_content'))
try:
    cid = get_case_id()
    if not cid:
        raise ValueError('Missing IRIS case_id')
    title, content = get_note_data()
    if not content:
        print(json.dumps({'status': 'skipped', 'case_id': cid, 'reason': 'No LLM note content'}, ensure_ascii=False))
    else:
        directory_response = post('/case/notes/directories/add?cid=' + str(cid), {'name': 'Automated Analysis', 'parent_id': None})
        directory_data = directory_response.get('data') or {}
        directory_id = directory_data.get('id') or directory_data.get('directory_id') or directory_data.get('group_id')
        if not directory_id:
            raise ValueError('IRIS did not return a directory ID: ' + json.dumps(directory_response, ensure_ascii=False))
        note_response = post('/case/notes/add?cid=' + str(cid), {'note_title': title or 'Automated Behavioral Context Analysis', 'note_content': content, 'directory_id': directory_id})
        print(json.dumps({'status': 'ok', 'case_id': cid, 'directory_id': directory_id, 'note_id': note_response.get('data', {}).get('note_id'), 'note_response': note_response}, ensure_ascii=False))
except Exception as e:
    print(json.dumps({'status': 'error', 'reason': type(e).__name__, 'detail': str(e)}, ensure_ascii=False))
