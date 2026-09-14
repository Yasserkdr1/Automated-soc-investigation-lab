
# Security notes

- The Shuffle export in this repository is sanitized. Real API keys and local credentials are intentionally absent.
- Never commit `.env`, Wazuh credentials, IRIS tokens, Groq keys, VirusTotal keys or AbuseIPDB keys.
- Rotate any credential that has ever been published outside the lab.
- Keep Wazuh, Shuffle and IRIS interfaces private to the lab network.
- The supplied IRIS scripts disable TLS certificate verification for the isolated lab; enable verification outside it.
- Use controlled ATT&CK simulations only on systems you own or are authorized to test.
