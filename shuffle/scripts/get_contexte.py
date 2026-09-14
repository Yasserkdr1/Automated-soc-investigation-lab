# Shuffle step: fetch nearby Wazuh events for behavioral context.
import json
import urllib.request
import urllib.error
import ssl
import base64
import re
from collections import Counter
NORMALIZED_ALERT = '$normalizer.message'
INDEXER_URL = '$wazuh_indexer_url'
INDEXER_USER = '$wazuh_indexer_user'
INDEXER_PASS = '$wazuh_indexer_pass'
INDEX_PATTERN = '$wazuh_indexer_index_pattern'
FETCH_LIMIT = 50
MAX_EVENTS = 10
MAX_PER_RULE = 3
VERIFY_TLS = False

def jload(v):
    if isinstance(v, dict):
        return v
    try:
        return json.loads(v)
    except Exception:
        return None

def short(v, n):
    if not isinstance(v, str):
        return v
    return v if len(v) <= n else v[:n] + '...'

def clean(d):
    return {k: v for k, v in d.items() if v not in (None, '', [], {})}

def auth():
    x = base64.b64encode(f'{INDEXER_USER}:{INDEXER_PASS}'.encode()).decode()
    return 'Basic ' + x

def sslctx():
    if VERIFY_TLS:
        return ssl.create_default_context()
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

def query(agent, start, end):
    return {'size': FETCH_LIMIT, 'sort': [{'timestamp': {'order': 'asc'}}], 'query': {'bool': {'filter': [{'term': {'agent.id': agent}}, {'range': {'timestamp': {'gte': start, 'lt': end}}}]}}, '_source': ['timestamp', 'rule.id', 'rule.level', 'rule.description', 'rule.mitre', 'data.win.eventdata', 'data.win.system.eventID', 'data.win.system.systemTime', 'data.audit', 'decoder.name', 'decoder.parent', 'full_log']}

def search(q):
    url = INDEXER_URL.rstrip('/') + '/' + INDEX_PATTERN + '/_search'
    req = urllib.request.Request(url, data=json.dumps(q).encode(), method='POST', headers={'Content-Type': 'application/json', 'Authorization': auth()})
    with urllib.request.urlopen(req, context=sslctx(), timeout=15) as r:
        return json.loads(r.read().decode())

def audit_raw_evidence(full_log):
    result = {'execve_raw': None, 'execve_a3_raw': None, 'proctitle_raw': None, 'uid_name': None, 'euid_name': None}
    if not isinstance(full_log, str) or not full_log:
        return result
    m = re.search('type=EXECVE\\b.*?(?=\\s+type=CWD\\b|\\x1d|$)', full_log, re.IGNORECASE | re.DOTALL)
    if m:
        execve_raw = m.group(0).strip()
        result['execve_raw'] = short(execve_raw, 900)
        a3 = re.search('\\ba3=(?:"([^"]*)"|([^\\s]+))', execve_raw, re.IGNORECASE)
        if a3:
            result['execve_a3_raw'] = a3.group(1) if a3.group(1) is not None else a3.group(2)
    p = re.search('\\bproctitle=([A-Fa-f0-9]+)', full_log)
    if p:
        result['proctitle_raw'] = short(p.group(1), 900)
    uid_match = re.search('\\bUID="([^"]+)"', full_log)
    if uid_match:
        result['uid_name'] = uid_match.group(1)
    euid_match = re.search('\\bEUID="([^"]+)"', full_log)
    if euid_match:
        result['euid_name'] = euid_match.group(1)
    return result

def compact_event(src):
    rule = src.get('rule') or {}
    mitre = rule.get('mitre') or {}
    data = src.get('data') or {}
    win = data.get('win') or {}
    e = win.get('eventdata') or {}
    sys = win.get('system') or {}
    process = clean({'image': short(e.get('image'), 180), 'command': short(e.get('commandLine'), 280), 'parent': short(e.get('parentImage'), 180), 'parent_command': short(e.get('parentCommandLine'), 220), 'user': e.get('user'), 'integrity': e.get('integrityLevel')})
    activity = clean({'script': short(e.get('scriptBlockText'), 320), 'target_file': short(e.get('targetFilename'), 180), 'target_object': short(e.get('targetObject'), 180), 'image_loaded': short(e.get('imageLoaded'), 180), 'source_ip': e.get('sourceIp') or e.get('srcIp') or e.get('ipAddress'), 'destination_ip': e.get('destinationIp') or e.get('destIp'), 'destination_port': e.get('destinationPort'), 'target_user': e.get('targetUserName'), 'logon_type': e.get('logonType')})
    audit = data.get('audit') or {}
    execve = audit.get('execve') or {}
    decoder = src.get('decoder') or {}
    raw = audit_raw_evidence(src.get('full_log'))
    linux = clean({'decoder': decoder.get('name'), 'exe': short(audit.get('exe'), 180), 'command': short(audit.get('command'), 120), 'cwd': short(audit.get('cwd'), 180), 'uid': audit.get('uid'), 'euid': audit.get('euid'), 'gid': audit.get('gid'), 'egid': audit.get('egid'), 'uid_name': raw.get('uid_name'), 'euid_name': raw.get('euid_name'), 'pid': audit.get('pid'), 'ppid': audit.get('ppid'), 'success': audit.get('success'), 'exit': audit.get('exit'), 'syscall': audit.get('syscall'), 'tty': audit.get('tty'), 'audit_key': audit.get('key'), 'execve_argc': execve.get('argc'), 'execve_a0': short(execve.get('a0'), 180), 'execve_a1': short(execve.get('a1'), 180), 'execve_a2': short(execve.get('a2'), 240), 'execve_a3': short(execve.get('a3'), 500), 'execve_a3_raw': short(raw.get('execve_a3_raw'), 500), 'execve_raw': raw.get('execve_raw'), 'proctitle_raw': raw.get('proctitle_raw')})
    return clean({'time': sys.get('systemTime') or e.get('utcTime') or src.get('timestamp'), 'rule': clean({'id': rule.get('id'), 'level': rule.get('level'), 'description': short(rule.get('description'), 180)}), 'mitre_ids': mitre.get('id'), 'event_id': sys.get('eventID') or audit.get('id'), 'process': process, 'activity': activity, 'linux': linux})

def relevance(ev):
    r = ev.get('rule') or {}
    p = ev.get('process') or {}
    a = ev.get('activity') or {}
    l = ev.get('linux') or {}
    score = (r.get('level') or 0) * 5
    if ev.get('mitre_ids'):
        score += 5
    if p.get('command'):
        score += 8
    if p.get('parent'):
        score += 4
    if p.get('integrity'):
        score += 3
    if a.get('script'):
        score += 10
    if a.get('target_file'):
        score += 7
    if a.get('target_object'):
        score += 7
    if a.get('image_loaded'):
        score += 4
    if a.get('source_ip'):
        score += 5
    if a.get('destination_ip'):
        score += 7
    if a.get('target_user'):
        score += 5
    if l.get('exe'):
        score += 8
    if l.get('cwd'):
        score += 4
    if l.get('audit_key'):
        score += 5
    if l.get('ppid'):
        score += 3
    if l.get('execve_a0'):
        score += 5
    if l.get('execve_a3_raw'):
        score += 12
    if l.get('proctitle_raw'):
        score += 12
    if l.get('execve_raw'):
        score += 5
    return score

def select_events(events):
    events.sort(key=relevance, reverse=True)
    selected = []
    per_rule = Counter()
    for event in events:
        rid = str((event.get('rule') or {}).get('id') or 'none')
        if per_rule[rid] >= MAX_PER_RULE:
            continue
        selected.append(event)
        per_rule[rid] += 1
        if len(selected) >= MAX_EVENTS:
            break
    selected.sort(key=lambda x: x.get('time') or '')
    return selected

def fetch(n):
    ctx = n.get('context_query') or {}
    agent = ctx.get('agent_id')
    start = ctx.get('from')
    end = ctx.get('to')
    if not agent or not start or (not end):
        return {'status': 'skipped', 'reason': 'missing_context_query', 'events': []}
    try:
        resp = search(query(agent, start, end))
    except urllib.error.HTTPError as e:
        return {'status': 'error', 'reason': f'http_{e.code}', 'detail': e.read().decode('utf-8', errors='replace')[:300], 'events': []}
    except Exception as e:
        return {'status': 'error', 'reason': type(e).__name__, 'detail': str(e), 'events': []}
    hits = resp.get('hits', {}).get('hits', [])
    events = [compact_event(h.get('_source') or {}) for h in hits]
    selected = select_events(events)
    rule_counts = Counter((str((event.get('rule') or {}).get('id')) for event in events if (event.get('rule') or {}).get('id')))
    top_rules = [{'rule_id': rid, 'count': count} for rid, count in rule_counts.most_common(6)]
    total = resp.get('hits', {}).get('total', 0)
    if isinstance(total, dict):
        total = total.get('value', 0)
    return {'status': 'ok', 'agent_id': agent, 'window': {'from': start, 'to': end}, 'total_matched': total, 'fetched': len(hits), 'selected': len(selected), 'top_rules': top_rules, 'events': selected}
try:
    n = jload(NORMALIZED_ALERT)
    if not n:
        raise ValueError('Invalid normalizer output')
    print(json.dumps(fetch(n), ensure_ascii=False))
except Exception as e:
    print(json.dumps({'status': 'error', 'reason': type(e).__name__, 'detail': str(e), 'events': []}, ensure_ascii=False))
