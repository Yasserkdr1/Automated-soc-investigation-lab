
# Wazuh detections

This repository contains the custom PowerShell download rule used by the lab and references the web-shell detection used for the Linux scenario.

## Rule coverage

| Rule | Level | Detection | ATT&CK |
|---|---:|---|---|
| `100401` | 10 | PowerShell `DownloadFile(...)` in Script Block Logging | T1105 |
| `100330` / `100331` | 12-class workflow | Multi-signal web-shell activity | T1505.003, T1059.004 |

The web-shell rules are maintained in the companion detection project:
https://github.com/Yasserkdr1/Wazuh-Multi-Signal-Web-Shell-Detection

## Collection expected by this lab

Windows should provide Sysmon, Wazuh Agent telemetry and PowerShell Operational logs (notably event 4104). The Linux web server path uses Apache/PHP telemetry together with Linux auditing/logging available to Wazuh.

Place the XML rule in the manager custom rules path, validate the ruleset, then restart the Wazuh manager. Adjust IDs only if they collide with existing local rules.
