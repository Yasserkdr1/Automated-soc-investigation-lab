
# DFIR-IRIS integration

IRIS is the investigation and case-management layer. The workflow prepares a case title/description, maps final risk to an IRIS severity, adds IOC targets when available and stores the behavioral analysis as a case note.

Current workflow behavior creates a case when the final risk score is `>= 35` (Medium or higher). This is intentionally visible in the repository because it is the threshold used by the supplied implementation; a stricter deployment can move the threshold to `>= 60`.

The Python integration uses bearer authentication and is configured with TLS verification disabled for the isolated lab. For any non-lab deployment, use valid TLS certificates and enable verification.

IOC type IDs used by the supplied script:

| Type | IRIS type ID |
|---|---:|
| Domain | 20 |
| IP (any) | 76 |
| SHA-256 | 113 |
| URL | 141 |
