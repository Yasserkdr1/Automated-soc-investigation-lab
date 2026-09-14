# Shuffle step: normalize supported Wazuh alerts and route observables.
import json, re, ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlsplit
RAW_INPUT = '$exec'
URL_RE = re.compile('https?://[^\\s"\\\'<>\\\\]+', re.I)
SHA256_KV_RE = re.compile('\\bSHA256\\s*=\\s*([A-Fa-f0-9]{64})\\b')
SHA256_BARE_RE = re.compile('^[A-Fa-f0-9]{64}$')

def dget(obj, path, default=None):
    cur = obj
    for k in path.split('.'):
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def uniq(values):
    out, seen = ([], set())
    for v in values or []:
        if v is None:
            continue
        if isinstance(v, str):
            v = v.strip()
            if not v:
                continue
        m = json.dumps(v, sort_keys=True, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
        if m not in seen:
            seen.add(m)
            out.append(v)
    return out

def clean(v):
    return v.replace('\\"', '"').replace("\\'", "'") if isinstance(v, str) else ''

def extract_urls(text):
    return uniq((m.group(0).rstrip(').,;') for m in URL_RE.finditer(clean(text))))

def extract_domains(urls):
    out = []
    for u in urls:
        try:
            h = urlsplit(u).hostname
            if h:
                out.append(h.lower().rstrip('.'))
        except Exception:
            continue
    return uniq(out)

def extract_download_target(script):
    c = clean(script)
    m = re.search('\\bDownloadFile\\s*\\(', c, re.I)
    if not m:
        return None
    q = re.findall('["\\\']([^"\\\']+)["\\\']', c[m.end():])
    return q[1].strip() if len(q) >= 2 else None

def extract_sha256(source):
    paths = ['data.win.eventdata.hashes', 'data.hashes', 'data.sha256', 'syscheck.sha256_after', 'syscheck.sha256_before']
    cands = []
    for p in paths:
        v = dget(source, p)
        if v is None:
            continue
        cands.extend(v if isinstance(v, list) else [v])
    hashes = []
    for c in cands:
        t = str(c).strip()
        hashes.extend((x.lower() for x in SHA256_KV_RE.findall(t)))
        if SHA256_BARE_RE.fullmatch(t):
            hashes.append(t.lower())
    return uniq(hashes)

def classify_ips(values):
    pub, priv, bad = ([], [], [])
    for raw in uniq(values):
        v = str(raw).strip()
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            bad.append(v)
            continue
        (pub if ip.is_global else priv).append(str(ip))
    return (uniq(pub), uniq(priv), uniq(bad))

def parse_ts(value):
    if not isinstance(value, str) or not value.strip():
        return None
    t = value.strip()
    m = re.search('([+-]\\d{2})(\\d{2})$', t)
    if m:
        t = t[:-5] + m.group(1) + ':' + m.group(2)
    if t.endswith('Z'):
        t = t[:-1] + '+00:00'
    try:
        return datetime.fromisoformat(t)
    except ValueError:
        return None

def iso_ms(dt):
    if dt is None:
        return None
    t = dt.isoformat(timespec='milliseconds')
    return t[:-6] + 'Z' if t.endswith('+00:00') else t

def context_window(timestamp, agent_id, minutes=10):
    end = parse_ts(timestamp)
    if end is None:
        return {'agent_id': agent_id, 'lookback_minutes': minutes, 'from': None, 'to': timestamp, 'end_exclusive': True}
    start = end - timedelta(minutes=minutes)
    return {'agent_id': agent_id, 'lookback_minutes': minutes, 'from': iso_ms(start), 'to': iso_ms(end), 'end_exclusive': True}

def parse_json_maybe(value):
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        raise TypeError('Input must be JSON text or a JSON object.')
    text = value.strip()
    if not text:
        raise ValueError('Shuffle input is empty.')
    parsed = json.loads(text)
    if isinstance(parsed, str):
        nested = parsed.strip()
        if nested.startswith('{') or nested.startswith('['):
            parsed = json.loads(nested)
    return parsed

def unwrap_payload(payload):
    if not isinstance(payload, dict):
        raise TypeError('Webhook payload must be a JSON object.')
    cur = payload
    if isinstance(cur.get('body'), str):
        try:
            b = json.loads(cur['body'])
            if isinstance(b, dict):
                cur = b
        except Exception:
            pass
    elif isinstance(cur.get('body'), dict):
        cur = cur['body']
    if isinstance(cur.get('all_fields'), dict):
        wrapper, af = (cur, dict(cur['all_fields']))
        af.setdefault('timestamp', wrapper.get('timestamp'))
        af.setdefault('id', wrapper.get('id'))
        if not isinstance(af.get('rule'), dict) and wrapper.get('rule_id'):
            af['rule'] = {'id': str(wrapper['rule_id'])}
        cur = af
    if isinstance(cur, dict) and isinstance(cur.get('_source'), dict):
        cur = cur['_source']
    if not isinstance(cur, dict):
        raise TypeError('Could not locate the Wazuh alert object.')
    return cur
HANDLERS = {}
ALERT_TYPES = {}

def register(rule_id, alert_type):

    def deco(fn):
        HANDLERS[rule_id] = fn
        ALERT_TYPES[rule_id] = alert_type
        return fn
    return deco

@register('100401', 'POWERSHELL_DOWNLOAD')
def handle_powershell_download(source, data):
    win = data.get('win') or {}
    eventdata = win.get('eventdata') or {}
    system = win.get('system') or {}
    script = eventdata.get('scriptBlockText')
    urls = extract_urls(script)
    domains = extract_domains(urls)
    warnings = [] if urls else ['no_url_extracted_from_script_block']
    return {'evidence': {'event_id': system.get('eventID'), 'channel': system.get('channel'), 'computer': system.get('computer'), 'process_id': system.get('processID'), 'script_block_id': eventdata.get('scriptBlockId'), 'script_block': script, 'download_target': extract_download_target(script)}, 'observables': {'urls': urls, 'domains': domains}, 'warnings': warnings}

@register('100330', 'WEBSHELL_ACTIVITY')
@register('100331', 'WEBSHELL_ACTIVITY')
def handle_webshell(source, data):
    audit = data.get('audit') if isinstance(data.get('audit'), dict) else {}
    source_ip = data.get('srcip')
    http_path = data.get('url')
    shell = audit.get('exe') or data.get('audit.exe') or data.get('exe')
    euid = audit.get('euid') or data.get('audit.euid')
    audit_key = audit.get('key') or data.get('audit.key')
    file_path = data.get('file') or audit.get('file') or data.get('path')
    pub, priv, bad = classify_ips([source_ip] if source_ip else [])
    warnings = [f"invalid_source_ip:{','.join(bad)}"] if bad else []
    urls, domains = ([], [])
    if isinstance(http_path, str) and http_path.startswith(('http://', 'https://')):
        urls = [http_path]
        domains = extract_domains(urls)
    return {'evidence': {'http_method': data.get('protocol'), 'http_status': str(data['id']) if data.get('id') is not None else None, 'http_path': http_path, 'source_ip': source_ip, 'shell': shell, 'effective_uid': str(euid) if euid is not None else None, 'audit_key': audit_key, 'file_path': file_path}, 'observables': {'urls': urls, 'domains': domains, 'public_ips': pub, 'private_or_non_global_ips': priv}, 'warnings': warnings}
EVIDENCE_KEYS = ['event_id', 'channel', 'computer', 'process_id', 'script_block_id', 'script_block', 'download_target', 'http_method', 'http_status', 'http_path', 'source_ip', 'shell', 'effective_uid', 'audit_key', 'file_path']
OBSERVABLE_KEYS = ['sha256', 'urls', 'domains', 'public_ips', 'private_or_non_global_ips']

def normalize_wazuh_alert(payload):
    source = unwrap_payload(payload)
    rule = source.get('rule') or {}
    agent = source.get('agent') or {}
    data = source.get('data') or {}
    rule_id = str(rule.get('id') or '')
    supported = rule_id in HANDLERS
    result = {'schema_version': '1.0', 'normalization_status': 'ok' if supported else 'unsupported', 'supported': supported, 'alert_type': ALERT_TYPES.get(rule_id, 'UNSUPPORTED'), 'trigger': {'alert_id': source.get('id'), 'timestamp': source.get('timestamp'), 'rule_id': rule_id or None, 'rule_level': rule.get('level'), 'rule_description': rule.get('description'), 'mitre_ids': uniq(dget(rule, 'mitre.id', []) or []), 'mitre_techniques': uniq(dget(rule, 'mitre.technique', []) or []), 'location': source.get('location'), 'decoder': dget(source, 'decoder.name')}, 'agent': {'id': agent.get('id'), 'name': agent.get('name'), 'ip': agent.get('ip')}, 'evidence': {k: None for k in EVIDENCE_KEYS}, 'observables': {k: [] for k in OBSERVABLE_KEYS}, 'routing': {'virustotal_hash': False, 'virustotal_domain': False, 'abuseipdb_ip': False}, 'enrichment_targets': {'virustotal_hashes': [], 'virustotal_domains': [], 'abuseipdb_ips': []}, 'context_query': context_window(source.get('timestamp'), agent.get('id')), 'get_contexte': False, 'warnings': []}
    if not supported:
        result['warnings'].append('unsupported_rule_id')
        return result
    result['observables']['sha256'] = extract_sha256(source)
    handler_out = HANDLERS[rule_id](source, data)
    result['evidence'].update(handler_out.get('evidence', {}))
    for k, v in handler_out.get('observables', {}).items():
        result['observables'][k] = v
    result['warnings'].extend(handler_out.get('warnings', []))
    result['enrichment_targets']['virustotal_hashes'] = uniq(result['observables']['sha256'])
    result['enrichment_targets']['virustotal_domains'] = uniq(result['observables']['domains'])
    result['enrichment_targets']['abuseipdb_ips'] = uniq(result['observables']['public_ips'])
    result['routing']['virustotal_hash'] = bool(result['enrichment_targets']['virustotal_hashes'])
    result['routing']['virustotal_domain'] = bool(result['enrichment_targets']['virustotal_domains'])
    result['routing']['abuseipdb_ip'] = bool(result['enrichment_targets']['abuseipdb_ips'])
    if not any(result['routing'].values()):
        result['warnings'].append('no_external_enrichment_needed')
    if result['routing']['virustotal_hash'] == False and result['routing']['virustotal_domain'] == False and (result['routing']['abuseipdb_ip'] == False):
        result['get_contexte'] = True
    return result
try:
    normalized = normalize_wazuh_alert(parse_json_maybe(RAW_INPUT))
    print(json.dumps(normalized, ensure_ascii=False))
except Exception as e:
    print(json.dumps({'schema_version': '1.0', 'normalization_status': 'error', 'supported': False, 'error_type': type(e).__name__, 'error': str(e)}, ensure_ascii=False))
