# Risk and Decision Model

The workflow keeps the original Wazuh detection severity separate from the SOAR risk score. `rule.level` is preserved as source evidence and is never overwritten by Shuffle.

The implemented model has three stages:

1. score each deterministic source independently;
2. combine those source scores into a deterministic risk score using dominant-evidence weighting;
3. when behavioral analysis is available, combine deterministic risk with the LLM context score and produce the final decision.

## 1. Deterministic inputs

The normalizer extracts supported observables and routes only the enrichment actions that have usable targets:

| Observable | Enrichment | Deterministic source |
|---|---|---|
| SHA-256 | VirusTotal | `vt_hash` |
| Domain | VirusTotal | `vt_domain` |
| Public IP | AbuseIPDB | `abuseipdb` |
| Wazuh rule level | Local mapping | `wazuh` |

Private or non-global IP addresses are kept in the normalized alert but are not sent to AbuseIPDB.

URLs can be extracted by the normalizer, but the current deterministic scoring code does **not** calculate a separate VirusTotal URL score. The implemented hash scoring path is SHA-256 only.

## 2. Wazuh source score

`ioc_enrichement_merge.py` converts the original Wazuh `rule.level` into a deterministic source score:

| Wazuh rule level | Source score |
|---:|---:|
| 1–4 | 10 |
| 5–7 | 20 |
| 8–9 | 30 |
| 10–11 | 40 |
| 12–13 | 50 |
| 14 | 60 |
| 15+ | 70 |

This mapped value participates in SOAR scoring, but the original Wazuh level remains unchanged in the alert data.

## 3. VirusTotal hash score

For every VirusTotal SHA-256 result, the workflow reads `last_analysis_stats` and calculates:

```text
hash_score = malicious × 10 + suspicious × 4
hash_score = min(100, hash_score)
```

The corresponding IOC verdict is assigned as follows:

```text
malicious >= 3                       -> malicious
malicious >= 1 OR suspicious >= 1   -> suspicious
otherwise                            -> no_malicious_detection
```

When several SHA-256 hashes are enriched, the workflow retains the score of **each IOC** in `ioc_details`, but the deterministic source score `vt_hash` is the **maximum hash score** observed:

```text
vt_hash = max(all hash scores)
```

This means a strong malicious hash is not diluted by other clean or weakly detected hashes.

Example based directly on the implemented formula:

```text
VirusTotal malicious detections = 59
VirusTotal suspicious detections = 0

hash_score = 59 × 10
           = 590
           -> capped at 100

vt_hash = 100
```

Therefore, a hash detected as malicious by `59/69` engines produces a `vt_hash` source score of `100`. The denominator is not part of the calculation; the code uses the malicious and suspicious counts returned in `last_analysis_stats`.

## 4. VirusTotal domain score

For every enriched domain, the workflow calculates:

```text
domain_score = malicious × 8 + suspicious × 3
domain_score = min(100, domain_score)
```

The IOC verdict uses the same detection-count logic as the hash branch:

```text
malicious >= 3                       -> malicious
malicious >= 1 OR suspicious >= 1   -> suspicious
otherwise                            -> no_malicious_detection
```

If several domains are present, all details are retained, while the deterministic source score is the strongest domain result:

```text
vt_domain = max(all domain scores)
```

## 5. AbuseIPDB IP score

For each public IP returned by AbuseIPDB, the workflow directly uses `abuseConfidenceScore` as that IOC's score:

```text
ip_score = abuseConfidenceScore
```

The implemented verdict mapping is:

```text
score >= 80   -> high_abuse
score >= 30   -> suspicious
score < 30    -> low_abuse
```

When several public IPs are enriched, all IOC results remain available in `ioc_details`, while the deterministic source score is the maximum value:

```text
abuseipdb = max(all IP scores)
```

## 6. Deterministic dominant-evidence combination

After calculating the available source scores, the workflow combines:

```text
wazuh
vt_hash
vt_domain
abuseipdb
```

Only source scores greater than zero are included. The values are sorted from highest to lowest and the four weights are applied in this order:

```text
1st / strongest source   × 1.00
2nd source               × 0.20
3rd source               × 0.10
4th source               × 0.05
```

The implementation is equivalent to:

```text
deterministic_risk = strongest × 1.00
                   + second    × 0.20
                   + third     × 0.10
                   + fourth    × 0.05

deterministic_risk = min(100, deterministic_risk)
```

The result is rounded to one decimal place.

### Why the strongest source is dominant

This is not an average. The strongest source keeps **100% of its score**. Weaker sources cannot lower it; they can only add supporting weight.

For example:

```text
vt_hash = 100
wazuh   = 30
```

The strongest source already contributes:

```text
100 × 1.00 = 100
```

Any additional positive source can only add evidence before the final cap is applied. The deterministic result therefore remains `100` / `Critical`.

This is the behavior that protects a very strong IOC result from being diluted by lower Wazuh, domain, or IP scores.

## 7. Deterministic risk verdict

The deterministic score is classified by `ioc_enrichement_merge.py` as:

```text
0–34    low
35–59   medium
60–79   high
80–100  critical
```

The same step sets:

```text
skip_llm_recommended = deterministic_risk >= 80
```

In the current Shuffle workflow:

```text
deterministic risk >= 80
        -> Final_decision directly

deterministic risk < 80
        -> Get_Contexte
        -> LLM-Analysis_Groq
        -> Final_decision
```

The normalizer also sets `get_contexte = true` when there is no hash, domain, or public-IP enrichment route available, allowing the behavioral path to provide context when external IOC enrichment is not applicable.

## 8. Behavioral context score

`Get_Contexte` queries Wazuh events for the same agent in the 10-minute window before the trigger timestamp. It fetches up to 50 matching events, then selects up to 10 events, with at most 3 selected events per rule, using the relevance function implemented in `get_contexte.py`.

The LLM receives the normalized trigger and the selected context events. Its prompt requires an evidence-based `context_risk_score` from 0 to 100 and explicitly separates observed behavior from inference.

The prompt defines these behavioral ranges:

```text
0–19    benign
20–34   likely_benign
35–49   uncertain
50–69   suspicious
70–89   highly_suspicious
90–100  malicious
```

`confidence` is a separate value and is not used as a second risk score.

## 9. Final deterministic + behavioral decision

`final_decision.py` combines the deterministic score and the behavioral-context score using a second dominant-source rule.

If both scores exist, the higher score becomes the dominant score:

```text
high = max(deterministic, behavioral_context)
low  = min(deterministic, behavioral_context)
```

The lower score contributes only when it is at least `35`:

```text
support_boost = low × 0.15    if low >= 35
support_boost = 0             if low < 35
```

The final score is:

```text
final_risk = high + support_boost
final_risk = min(100, final_risk)
```

This means the weaker analysis branch can never reduce the stronger one.

Example:

```text
deterministic = 72
behavioral     = 50

high = 72
low  = 50
support_boost = 50 × 0.15 = 7.5

final = 79.5
```

`final_decision.py` then rounds the final score to an integer.

If only one of the two scores exists, that score is used without a support boost. If neither deterministic nor behavioral risk is usable, the code falls back to the Wazuh level mapping.

## 10. Final risk level and response action

The final SOAR score uses these severity thresholds:

```text
0–34    LOW
35–59   MEDIUM
60–79   HIGH
80–100  CRITICAL
```

The automated action mapping is separate:

```text
score >= 60   -> escalate
score >= 35   -> review
score >= 20   -> monitor
score < 20    -> close
```

IRIS priority is assigned as:

```text
score >= 80   -> urgent
score >= 60   -> high
score >= 35   -> normal
score < 35    -> low
```

## 11. Values kept separate

The final decision preserves the different layers instead of replacing one with another:

```text
Wazuh rule.level
        -> original SIEM detection severity

source_scores
        -> wazuh / vt_hash / vt_domain / abuseipdb

deterministic risk_score
        -> combined deterministic evidence

context_risk_score
        -> behavioral LLM assessment when available

final_risk_score
        -> final SOAR decision score
```

The output also records `dominant_source`, which is either `deterministic`, `behavioral_context`, or `wazuh_fallback` depending on the evidence available to `final_decision.py`.

## 12. Current model boundaries

The following points reflect the current implementation:

- SHA-256 is the only hash type scored by the deterministic enrichment code.
- VirusTotal hash and domain results are scored separately.
- AbuseIPDB is used only for public IP enrichment.
- Private/non-global IPs are not sent to AbuseIPDB.
- URLs may be normalized but currently have no dedicated deterministic URL risk formula.
- When several IOCs of the same type exist, the strongest score represents that source; the individual IOC results are still retained in `ioc_details`.
- Deterministic sources are not averaged. The strongest source receives weight `1.00` and therefore cannot be diluted by weaker sources.
- A deterministic score of `80` or more follows the workflow's direct path to the final decision without the LLM branch.
- Wazuh `rule.level` is preserved and is not replaced by the SOAR score.

The model is intentionally deterministic and explainable: each IOC has a visible source score, the strongest evidence remains dominant, and the final behavioral combination cannot lower an already stronger deterministic result.
