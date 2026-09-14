# Shuffle step: merge deterministic IOC enrichment into a risk score.
import json
NORMALIZED_RAW = '$normalizer.message'
VT_HASH_RAW = '$vt_hash'
VT_DOMAIN_RAW = '$vt_domain'
ABUSEIPDB_RAW = '$abuseipdb_v2_1'

def jload(v):
    if isinstance(v, (dict, list)):
        return v
    if not isinstance(v, str):
        return None
    v = v.strip()
    if not v or v.startswith('$'):
        return None
    try:
        x = json.loads(v)
        if isinstance(x, str) and x.strip().startswith(('{', '[')):
            x = json.loads(x)
        return x
    except:
        return None

def unwrap(raw):
    x = jload(raw)
    if x is None:
        return []
    if not isinstance(x, list):
        x = [x]
    out = []
    for item in x:
        if not isinstance(item, dict):
            continue
        body = item.get('body', item)
        if isinstance(body, str):
            body = jload(body)
        if isinstance(body, dict):
            out.append(body)
    return out

def normalized():
    x = jload(NORMALIZED_RAW)
    if not isinstance(x, dict):
        return {}
    return x['message'] if isinstance(x.get('message'), dict) else x

def wazuh_score(level):
    try:
        level = int(level)
    except:
        return None
    if level <= 0:
        return None
    if level <= 4:
        return 10
    if level <= 7:
        return 20
    if level <= 9:
        return 30
    if level <= 11:
        return 40
    if level <= 13:
        return 50
    if level == 14:
        return 60
    return 70

def vt_results(raw, ioc_type):
    scores = []
    details = []
    for response in unwrap(raw):
        data = response.get('data')
        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            continue
        for obj in items:
            if not isinstance(obj, dict):
                continue
            value = obj.get('id')
            attrs = obj.get('attributes') or {}
            stats = attrs.get('last_analysis_stats') or {}
            if not value or not stats:
                continue
            malicious = int(stats.get('malicious') or 0)
            suspicious = int(stats.get('suspicious') or 0)
            harmless = int(stats.get('harmless') or 0)
            undetected = int(stats.get('undetected') or 0)
            if ioc_type == 'sha256':
                score = min(100, malicious * 10 + suspicious * 4)
            else:
                score = min(100, malicious * 8 + suspicious * 3)
            if malicious >= 3:
                verdict = 'malicious'
            elif malicious >= 1 or suspicious >= 1:
                verdict = 'suspicious'
            else:
                verdict = 'no_malicious_detection'
            scores.append(score)
            details.append({'type': ioc_type, 'value': value, 'provider': 'VirusTotal', 'score': score, 'verdict': verdict, 'malicious': malicious, 'suspicious': suspicious, 'harmless': harmless, 'undetected': undetected})
    return (max(scores) if scores else None, details)

def abuse_results(raw):
    scores = []
    details = []
    for response in unwrap(raw):
        data = response.get('data')
        if not isinstance(data, dict):
            continue
        value = data.get('ipAddress') or data.get('ip')
        if not value:
            continue
        score = int(data.get('abuseConfidenceScore') or 0)
        if score >= 80:
            verdict = 'high_abuse'
        elif score >= 30:
            verdict = 'suspicious'
        else:
            verdict = 'low_abuse'
        scores.append(score)
        details.append({'type': 'ip', 'value': value, 'provider': 'AbuseIPDB', 'score': score, 'verdict': verdict, 'abuse_confidence': score, 'total_reports': data.get('totalReports'), 'country': data.get('countryCode')})
    return (max(scores) if scores else None, details)

def combine(scores):
    values = [float(x) for x in scores if x is not None and float(x) > 0]
    if not values:
        return 0
    values.sort(reverse=True)
    weights = [1.0, 0.2, 0.1, 0.05]
    final = 0
    for i, value in enumerate(values[:4]):
        final += value * weights[i]
    return min(100, round(final, 1))

def verdict(score):
    if score >= 80:
        return 'critical'
    if score >= 60:
        return 'high'
    if score >= 35:
        return 'medium'
    return 'low'
try:
    n = normalized()
    trigger = n.get('trigger') or {}
    wazuh = wazuh_score(trigger.get('rule_level'))
    vt_hash, hash_details = vt_results(VT_HASH_RAW, 'sha256')
    vt_domain, domain_details = vt_results(VT_DOMAIN_RAW, 'domain')
    abuseipdb, ip_details = abuse_results(ABUSEIPDB_RAW)
    risk_score = combine([wazuh, vt_hash, vt_domain, abuseipdb])
    result = {'risk_score': risk_score, 'risk_verdict': verdict(risk_score), 'skip_llm_recommended': risk_score >= 80, 'reason': None, 'source_scores': {'wazuh': wazuh, 'vt_hash': vt_hash, 'vt_domain': vt_domain, 'abuseipdb': abuseipdb}, 'ioc_details': hash_details + domain_details + ip_details}
    print(json.dumps(result, ensure_ascii=False))
except Exception as e:
    print(json.dumps({'risk_score': 0, 'risk_verdict': 'unknown', 'skip_llm_recommended': False, 'reason': type(e).__name__, 'detail': str(e), 'source_scores': {'wazuh': None, 'vt_hash': None, 'vt_domain': None, 'abuseipdb': None}, 'ioc_details': []}, ensure_ascii=False))
