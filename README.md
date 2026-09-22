
# Automated Soc investigation Lab

> A modular SOC lab that detects endpoint/server activity with Wazuh, performs conditional enrichment and behavioral triage in Shuffle, calculates a separate incident risk score, and opens structured investigations in DFIR-IRIS.

<p>
  <img src="https://img.shields.io/badge/Wazuh-SIEM-1668DC?style=flat-square" alt="Wazuh">
  <img src="https://img.shields.io/badge/Sysmon-Windows%20Telemetry-0078D4?style=flat-square&logo=windows" alt="Sysmon">
  <img src="https://img.shields.io/badge/Shuffle-SOAR-F97316?style=flat-square" alt="Shuffle">
  <img src="https://img.shields.io/badge/Python-Automation-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Docker-Containers-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/DFIR--IRIS-Case%20Management-155EEF?style=flat-square" alt="DFIR-IRIS">
  <img src="https://img.shields.io/badge/Atomic%20Red%20Team-ATT%26CK%20Simulation-B91C1C?style=flat-square" alt="Atomic Red Team">
</p>

## Architecture

<p align="center">
  <img src="architecture/deployment-architecture.png" alt="Automated SOC lab architecture" width="100%">
</p>

The lab runs Wazuh, Shuffle and DFIR-IRIS as separate SOC services on the same bridged lab network. A Windows endpoint provides Sysmon/PowerShell telemetry and a Linux Apache/PHP server provides web/audit telemetry. Shuffle can reach VirusTotal, AbuseIPDB and an OpenAI-compatible Groq endpoint for enrichment and behavioral analysis.

## What the pipeline does

```text
Endpoint / Server telemetry
        -> Wazuh detection
        -> Shuffle webhook
        -> Normalize + extract observables
        -> Conditional IOC enrichment
        -> Optional Wazuh context lookup + LLM behavioral triage
        -> Final contextual risk score
        -> DFIR-IRIS case, severity, IOC(s) and analyst note
```

The key design choice is **conditional automation**: no hash means no hash lookup; private IPs are not sent to AbuseIPDB; an alert with no external IOC can still be analyzed using surrounding telemetry. Wazuh `rule.level` remains unchanged and is stored separately from the SOAR risk score.

## Implemented detection paths

| Scenario | Wazuh rule | ATT&CK | Main evidence |
|---|---|---|---|
| PowerShell remote file download | `100401` | T1105 | PowerShell 4104, URL/domain, optional hash/context |
| Multi-signal web-shell activity | `100330` / `100331` | T1505.003, T1059.004 | Apache/PHP request + Linux audit/shell context |

The PowerShell samples include both a benign text-file download and a Mimikatz archive download. The automation does not claim execution when the evidence only proves download activity.

## Shuffle workflow

```mermaid

flowchart TD

    ENDPOINT[Endpoint Machines<br/>Windows 10 / Ubuntu Server]
    TEL[Collect Telemetry<br/>Sysmon / PowerShell / auditd / journald / Apache]
    AGENT[Wazuh Agent]
    WAZUH[Wazuh Manager / SIEM]

    ENDPOINT --> TEL
    TEL --> AGENT
    AGENT --> WAZUH

    WAZUH -->|Alert JSON| SHUFFLE[Shuffle SOAR]

    SHUFFLE --> NORMALIZE[Normalize Alert]
    NORMALIZE --> EXTRACT[Extract Available IOCs]

    EXTRACT --> IOC_CHECK{IOC Available?}

    IOC_CHECK -->|Yes| IOC_TYPE{IOC Type?}
    IOC_CHECK -->|No| CONTEXT[Retrieve Wazuh Context]

    IOC_TYPE -->|SHA-256| VTHASH[VirusTotal<br/>Hash Enrichment]
    IOC_TYPE -->|Domain| VTDOMAIN[VirusTotal<br/>Domain Enrichment]
    IOC_TYPE -->|Public IP| ABUSEIP[AbuseIPDB<br/>IP Enrichment]

    VTHASH --> DETSCORE[Deterministic Risk Scoring]
    VTDOMAIN --> DETSCORE
    ABUSEIP --> DETSCORE

    DETSCORE --> EVIDENCE{Strong Deterministic<br/>Evidence?}

    EVIDENCE -->|Yes| FINAL[Final Decision]
    EVIDENCE -->|No| CONTEXT

    CONTEXT --> LLM[LLM-Assisted<br/>Contextual Analysis]
    LLM --> FINAL

    FINAL --> RISK[Final Risk Score<br/>& Severity]
    RISK --> IRIS[Create DFIR-IRIS Case]

    IRIS --> SEVERITY[Set Case Severity]
    IRIS --> IOC[Add Available IOCs]
    IRIS --> NOTE[Add Investigation Context]


    %% =========================
    %% STYLING
    %% =========================

    classDef process fill:#ffffff,stroke:#7c3aed,stroke-width:1.5px,color:#1f2937;
    classDef decision fill:#f5f3ff,stroke:#6d28d9,stroke-width:1.8px,color:#2e1065;
    classDef system fill:#fafafa,stroke:#7c3aed,stroke-width:1.5px,color:#1f2937;
    classDef output fill:#faf5ff,stroke:#7c3aed,stroke-width:1.5px,color:#2e1065;

    class ENDPOINT,AGENT,WAZUH,SHUFFLE,IRIS system;
    class TEL,NORMALIZE,EXTRACT,CONTEXT,VTHASH,VTDOMAIN,ABUSEIP,DETSCORE,LLM process;
    class IOC_CHECK,IOC_TYPE,EVIDENCE decision;
    class FINAL,RISK,SEVERITY,IOC,NOTE output;

    linkStyle default stroke:#7c3aed,stroke-width:1.4px;


```


<p align="center">
  <img src="architecture/shuffle-workflow.jpg" alt="Shuffle workflow" width="900">
</p>



The workflow has four practical stages: normalize/routing, deterministic enrichment, contextual analysis, and IRIS handoff. VirusTotal handles domain/hash reputation, AbuseIPDB handles eligible public IPs, Wazuh supplies nearby events, and the behavioral branch uses a constrained JSON prompt that explicitly distinguishes observation from inference.

### Risk logic

Deterministic evidence and behavioral context are scored independently. The final decision keeps the stronger signal and can apply a small support boost when both sources are materially suspicious. Current bands are `Low <35`, `Medium 35–59`, `High 60–79`, `Critical >=80`. this threshold is intentionally documented and can be tightened for a different lab policy. See [docs/risk-model.md](docs/risk-model.md).

## Repository layout

```text
automated-soc-lab/
├── architecture/        # deployment + workflow diagrams
├── wazuh/               # custom rule and detection notes
├── shuffle/             # sanitized workflow, Python steps, LLM request body
├── iris/                # case/severity payloads and IOC integration notes
├── scenarios/           # two end-to-end scenario write-ups
├── evidence/            # sanitized raw alerts + selected screenshots
└── docs/                # risk model, security notes, original build plan
```

## Quick start

1. Clone the repository and copy `.env.example` to a private local secret file; do not commit it.
2. Add the Wazuh custom rule and verify Windows PowerShell/Sysmon collection plus Linux web/audit telemetry.
3. Import `shuffle/workflow-shuffle.sanitized.json`, then re-bind VirusTotal, AbuseIPDB and IRIS authentication.
4. Set private Wazuh Indexer, Groq and IRIS variables in Shuffle.
5. Send a known Wazuh alert to the Shuffle webhook and verify normalization, conditional routing, final scoring and IRIS creation.

The supplied raw alerts under `evidence/raw-alerts/` can be used to inspect expected field shapes without exposing the original lab addresses/hostnames.

## Evidence

<table>
<tr>
<td width="50%"><img src="evidence/screenshots/01-iris-powershell-mimikatz.jpg" alt="IRIS PowerShell case"></td>
<td width="50%"><img src="evidence/screenshots/02-iris-powershell-mimikatz-note.jpg" alt="IRIS automated PowerShell note"></td>
</tr>
<tr>
<td width="50%"><img src="evidence/screenshots/04-iris-webshell-summary.jpg" alt="IRIS web-shell case"></td>
<td width="50%"><img src="evidence/screenshots/05-iris-webshell-llm-note.jpg" alt="IRIS automated web-shell note"></td>
</tr>
</table>

## Security and scope

This is a home lab / portfolio implementation, not a production SOC reference architecture. The scoring model is intentionally explainable rather than mathematically sophisticated. Automated containment is out of scope, and the LLM is used for contextual triage rather than as a replacement for deterministic detection or analyst judgment.

The public workflow export is sanitized; real API keys and credentials are not included. Lab-only TLS shortcuts remain visible in code so they are not mistaken for production-safe defaults. See [docs/security.md](docs/security.md).

## Related detection project

The Linux web-shell correlation rules are maintained in a companion repository:
https://github.com/Yasserkdr1/Wazuh-Multi-Signal-Web-Shell-Detection

## License

MIT — use, adapt and extend the lab for authorized security learning.
