# Shuffle step: combine deterministic and behavioral risk and prepare IRIS data.
import json
NORMALIZED_RAW = '$normalizer.message'
DETERMINISTIC_RAW = '$ioc_enrichement_merge.message'
LLM_RAW = '$llm-analysis_groq'
IRIS_CUSTOMER_ID = 1

def jload(v):
    if isinstance(v, (dict, list)):
        return v
    if not isinstance(v, str) or not v.strip() or v.strip().startswith('$'):
        return None
    try:
        x = json.loads(v)
        if isinstance(x, str) and x.strip().startswith(('{', '[')):
            x = json.loads(x)
        return x
    except:
        return None

def num(v):
    try:
        return max(0, min(100, float(v)))
    except:
        return None

def dct(v):
    return v if isinstance(v, dict) else {}

def lst(v):
    return v if isinstance(v, list) else []

def parse_normalized():
    x = jload(NORMALIZED_RAW)
    if not isinstance(x, dict):
        return {}
    return x['message'] if isinstance(x.get('message'), dict) else x

def parse_deterministic():
    x = jload(DETERMINISTIC_RAW)
    if not isinstance(x, dict):
        return None
    if 'risk_score' not in x and isinstance(x.get('message'), dict):
        x = x['message']
    score = num(x.get('risk_score'))
    if score is None:
        return None
    return {'score': score, 'risk_verdict': x.get('risk_verdict') or x.get('verdict') or x.get('risk_level'), 'skip_llm_recommended': x.get('skip_llm_recommended'), 'source_scores': x.get('source_scores') or x.get('scores'), 'ioc_details': lst(x.get('ioc_details'))}

def parse_llm():
    x = jload(LLM_RAW)
    if x is None:
        return None
    if isinstance(x, list):
        x = next((i for i in x if isinstance(i, dict) and i.get('status') == 200), x[0] if x else None)
    if not isinstance(x, dict):
        return None
    body = x.get('body')
    if body is not None:
        body = jload(body) if isinstance(body, str) else body
        if isinstance(body, dict):
            x = body
    choices = x.get('choices')
    if isinstance(choices, list) and choices:
        content = dct(choices[0].get('message')).get('content')
        parsed = jload(content)
        if isinstance(parsed, dict):
            x = parsed
    score = num(x.get('context_risk_score'))
    if score is None:
        return None
    return {'score': score, 'context_verdict': x.get('context_verdict'), 'confidence': num(x.get('confidence')), 'summary': x.get('summary'), 'attack_chain': x.get('attack_chain'), 'key_evidence': lst(x.get('key_evidence')), 'benign_context': lst(x.get('benign_context')), 'uncertainties': lst(x.get('uncertainties')), 'related_mitre': lst(x.get('related_mitre')), 'recommended_action': x.get('recommended_action')}

def wazuh_fallback(level):
    try:
        level = int(level)
    except:
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

def risk_level(score):
    if score >= 80:
        return 'CRITICAL'
    if score >= 60:
        return 'HIGH'
    if score >= 35:
        return 'MEDIUM'
    return 'LOW'

def action(score):
    if score >= 60:
        return 'escalate'
    if score >= 35:
        return 'review'
    if score >= 20:
        return 'monitor'
    return 'close'

def combine(det, ctx):
    if det is None and ctx is None:
        return (None, 0, None)
    if ctx is None:
        return (det, 0, 'deterministic')
    if det is None:
        return (ctx, 0, 'behavioral_context')
    if det >= ctx:
        high = det
        low = ctx
        source = 'deterministic'
    else:
        high = ctx
        low = det
        source = 'behavioral_context'
    boost = low * 0.15 if low >= 35 else 0
    return (min(100, high + boost), boost, source)

def iris_severity(level):
    return {'LOW': 4, 'MEDIUM': 1, 'HIGH': 5, 'CRITICAL': 6}.get(level, 2)

def iris_priority(score):
    if score >= 80:
        return 'urgent'
    if score >= 60:
        return 'high'
    if score >= 35:
        return 'normal'
    return 'low'

def build_title(n, severity):
    trigger = dct(n.get('trigger'))
    agent = dct(n.get('agent'))
    desc = trigger.get('rule_description') or n.get('alert_type') or 'Security Alert'
    host = agent.get('name') or agent.get('id') or 'unknown-endpoint'
    title = f'[{severity}] {desc} - {host}'
    return title[:177] + '...' if len(title) > 180 else title
IOC_TYPES = {'domain': 20, 'ip': 76, 'sha256': 113, 'url': 141}

def ioc_description(e):
    if not e:
        return 'IOC extracted automatically from Wazuh / Shuffle.'
    parts = ['IOC extracted automatically from Wazuh / Shuffle.']
    fields = [('Provider', 'provider', ''), ('Verdict', 'verdict', ''), ('IOC Risk Score', 'score', '/100'), ('Malicious detections', 'malicious', ''), ('Suspicious detections', 'suspicious', ''), ('Harmless detections', 'harmless', ''), ('Undetected vendors', 'undetected', ''), ('AbuseIPDB confidence', 'abuse_confidence', '%'), ('AbuseIPDB reports', 'total_reports', ''), ('Country', 'country', '')]
    for label, key, suffix in fields:
        value = e.get(key)
        if value is not None:
            parts.append(f'{label}: {value}{suffix}')
    return ' | '.join(parts)

def build_iocs(obs, details):
    sources = [('sha256', 'sha256'), ('url', 'urls'), ('domain', 'domains'), ('ip', 'public_ips')]
    detail_map = {}
    for item in details:
        if not isinstance(item, dict):
            continue
        typ = str(item.get('type') or '')
        value = str(item.get('value') or '')
        if typ and value:
            detail_map[typ, value] = item
    out = []
    seen = set()
    for typ, field in sources:
        for value in lst(obs.get(field)):
            if not value:
                continue
            key = (typ, str(value))
            if key in seen:
                continue
            seen.add(key)
            enrichment = detail_map.get(key)
            out.append({'type': typ, 'ioc_type_id': IOC_TYPES[typ], 'value': value, 'enrichment': enrichment, 'description': ioc_description(enrichment)})
    return out

def build_llm_note(llm, trigger):
    if not llm:
        return None
    confidence = int(round(llm['confidence'])) if llm.get('confidence') is not None else None
    confidence_text = f'{confidence}%' if confidence is not None else 'N/A'
    lines = ['Automated Behavioral Context Analysis', '', f"Wazuh Trigger: {trigger.get('rule_description') or 'N/A'}", f"Wazuh Rule: {trigger.get('rule_id') or 'N/A'}", f"Wazuh Level: {(trigger.get('rule_level') if trigger.get('rule_level') is not None else 'N/A')}", '', f"Context Risk Score: {int(round(llm['score']))}/100", f"Context Verdict: {llm.get('context_verdict') or 'N/A'}", f'Confidence: {confidence_text}', f"Attack Chain: {llm.get('attack_chain') or 'N/A'}", f"Recommended Action: {llm.get('recommended_action') or 'N/A'}", '', 'Context Summary:', str(llm.get('summary') or 'N/A')]
    evidence = lst(llm.get('key_evidence'))
    if evidence:
        lines += ['', 'Key Evidence:']
        for item in evidence:
            if isinstance(item, dict):
                lines.append('- [{}] {}'.format(str(item.get('severity', 'unknown')).upper(), item.get('finding', '')))
            else:
                lines.append(f'- {item}')
    benign = lst(llm.get('benign_context'))
    if benign:
        lines += ['', 'Benign Context:']
        for item in benign:
            lines.append(f'- {item}')
    uncertainties = lst(llm.get('uncertainties'))
    if uncertainties:
        lines += ['', 'Uncertainties:']
        for item in uncertainties:
            lines.append(f'- {item}')
    mitre = lst(llm.get('related_mitre'))
    if mitre:
        lines += ['', 'Related MITRE: ' + ', '.join((str(x) for x in mitre))]
    return '\n'.join(lines)

def main():
    warnings = []
    n = parse_normalized()
    det = parse_deterministic()
    llm = parse_llm()
    trigger = dct(n.get('trigger'))
    agent = dct(n.get('agent'))
    obs = dct(n.get('observables'))
    det_score = det['score'] if det else None
    ctx_score = llm['score'] if llm else None
    final, boost, dominant = combine(det_score, ctx_score)
    if det_score is not None and ctx_score is not None:
        mode = 'combined'
    elif det_score is not None:
        mode = 'deterministic_only'
    elif ctx_score is not None:
        mode = 'behavioral_only'
    else:
        mode = 'wazuh_fallback'
    if final is None:
        final = wazuh_fallback(trigger.get('rule_level'))
        dominant = 'wazuh_fallback'
        if final is None:
            return {'decision_status': 'error', 'create_iris_case': False, 'reason': 'No usable risk source'}
        warnings.append('deterministic_and_llm_scores_missing')
    final = int(round(final))
    severity = risk_level(final)
    create_case = final >= 35
    iocs = build_iocs(obs, det.get('ioc_details') if det else [])
    if dominant == 'behavioral_context' and llm:
        final_verdict = llm.get('context_verdict')
    elif dominant == 'deterministic' and det:
        final_verdict = det.get('risk_verdict')
    else:
        final_verdict = None
    final_verdict = final_verdict or (llm or {}).get('context_verdict') or (det or {}).get('risk_verdict') or severity.lower()
    return {'decision_status': 'ok', 'decision_mode': mode, 'scores': {'deterministic': int(round(det_score)) if det_score is not None else None, 'behavioral_context': int(round(ctx_score)) if ctx_score is not None else None, 'support_boost': round(boost, 2), 'final': final}, 'dominant_source': dominant, 'final_risk_score': final, 'final_risk_level': severity, 'final_verdict': final_verdict, 'final_action': action(final), 'create_iris_case': create_case, 'iris': {'customer_id': IRIS_CUSTOMER_ID, 'severity': severity, 'severity_id': iris_severity(severity), 'priority': iris_priority(final), 'title': build_title(n, severity), 'ioc_targets': iocs, 'llm_note_title': 'Automated Behavioral Context Analysis', 'llm_note_content': build_llm_note(llm, trigger), 'routing': {'create_case': create_case, 'set_severity': create_case, 'add_ioc': bool(create_case and iocs), 'add_llm_note': bool(create_case and llm)}}, 'alert': {'alert_id': trigger.get('alert_id'), 'alert_type': n.get('alert_type'), 'timestamp': trigger.get('timestamp'), 'rule_id': trigger.get('rule_id'), 'rule_level': trigger.get('rule_level'), 'rule_description': trigger.get('rule_description'), 'wazuh_mitre_ids': trigger.get('mitre_ids'), 'agent_id': agent.get('id'), 'agent_name': agent.get('name'), 'agent_ip': agent.get('ip')}, 'observables': obs, 'deterministic': det, 'behavioral_analysis': llm, 'warnings': warnings}
try:
    print(json.dumps(main(), ensure_ascii=False))
except Exception as e:
    print(json.dumps({'decision_status': 'error', 'reason': type(e).__name__, 'detail': str(e), 'create_iris_case': False}, ensure_ascii=False))
