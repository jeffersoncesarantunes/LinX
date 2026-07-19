# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅       |

## Reporting a Vulnerability

This is a forensic correlation tool designed for authorized security assessments. If you discover a security vulnerability, please do NOT open a public issue.

Contact the maintainer directly at jefferson.antunes@gmail.com with details about the issue.

We commit to acknowledging receipt within 48 hours and providing a fix timeline within 7 days.

## Known Limitations

- **JSON parsing trust boundary**: The tool trusts JSON input from LinSpec and K-Scanner. Malformed or malicious JSON could cause parsing errors. Validate inputs from untrusted sources.
- **TOCTOU in file reads**: The tool reads JSON files at a point in time. Between LinSpec/K-Scanner execution and correlation analysis, system state may change. This is an inherent limitation of multi-tool forensic pipelines.
- **Read-only analysis**: LinX performs no writes to kernel or process state. All analysis is passive.
