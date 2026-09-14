
# Shuffle SOAR workflow

`workflow-shuffle.sanitized.json` is the public-safe export of the working lab workflow. Credentials from the source export were removed.

## Flow

```text
Webhook
  -> Normalizer
      -> VirusTotal domain (when present)
      -> VirusTotal hash   (when present)
      -> AbuseIPDB IP      (public IP only)
  -> IOC enrichment merge
  -> Wazuh context lookup when deeper context is useful
  -> Groq/OpenAI-compatible behavioral analysis
  -> Final decision
  -> IRIS case -> severity -> IOC(s) -> analysis note
```

The deterministic IOC branch can recommend skipping the LLM when its risk is already `>= 80`. Alerts with no external IOC are routed directly to contextual analysis instead of failing enrichment.

## Import checklist

1. Import the sanitized JSON into Shuffle.
2. Re-bind application authentication for VirusTotal, AbuseIPDB and IRIS.
3. Set the Wazuh Indexer, Groq and IRIS workflow variables from private secrets.
4. Update the Wazuh-to-Shuffle webhook URL in your lab.
5. Run the supplied alert samples and verify the normalizer routes only observables that exist.

The Python files in `scripts/` mirror the code blocks used by the workflow and are kept separately so the logic can be reviewed without opening the Shuffle UI.
