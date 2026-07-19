# LinX

Lightweight forensic correlation engine that cross-references LinSpec audit results with K-Scanner memory analysis findings — connecting kernel hardening gaps to active memory threats.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Language-C99-00599C?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00A86B?style=flat-square)](#-roadmap)
[![Docker](https://img.shields.io/badge/Docker-Multi--stage-2496ED?style=flat-square&logo=docker)](Dockerfile)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Digital%20Forensics-8A2BE2?style=flat-square)](./docs/architecture.md)

---

## Etymology

**LinX** = **Linux** + **Cross-reference (Correlate)**.

The missing link between posture audit (LinSpec) and live memory analysis (K-Scanner) — answering not just *"what is vulnerable?"* but *"what is the combined risk?"*

---

## Overview

LinSpec tells you which kernel hardening parameters are misconfigured. K-Scanner tells you which processes have RWX memory regions. LinX connects these signals — identifying dangerous combinations like *"kptr_restrict=0 AND ASLR=0"* (KASLR bypass complete) or *"ptrace_scope=0 while K-Scanner detects RWX regions"* (injection path available).

**Correlation rules** across 3 categories:

| Category | Rules | Source |
|----------|-------|--------|
| Single-check | kptr_restrict, ptrace_scope, ASLR, dmesg, BPF, kexec, perf_event, userns | LinSpec |
| Cross-check | KASLR bypass chain, Kernel address disclosure chain | LinSpec + LinSpec |
| Memory | RWX region detection with severity classification | K-Scanner |

---

## Features

- Cross-references LinSpec and K-Scanner outputs automatically
- 8 single-check correlation rules with CVSS-aligned severity
- 2 multi-check composite rules (KASLR bypass, address disclosure)
- K-Scanner RWX findings classified by confidence level
- Pure C99, zero dependencies beyond POSIX
- JSON export for pipeline integration
- PIE + RELRO + FORTIFY hardened binary
- Natively compatible with the SYNTROPY ecosystem

---

## Screenshots

![LinX Screenshot 1](Images/linx1.png)
![LinX Screenshot 2](Images/linx2.png)

---

## Quick Start

```bash
git clone https://github.com/jeffersoncesarantunes/LinX.git
cd LinX

# Build the project
make

# Run with LinSpec report only
sudo ./linx --linspec /path/to/report.json

# Run with both LinSpec and K-Scanner
sudo ./linx -l report.json -k kscan_results.json -j
```

---

## Usage

```
LinX v1.0.0 - Forensic Correlation Engine
Usage: linx [options]

Options:
  -l, --linspec FILE   LinSpec report.json path
  -k, --kscanner FILE  K-Scanner results.json path
  -j, --json           Export JSON correlation report
  -o, --output-dir DIR Output directory (default: reports/)
  -V, --version        Show version
  -h, --help           Show this help
```

### Examples

```bash
# Correlate with LinSpec only
./linx -l reports/report.json

# Full correlation with both tools
./linx -l reports/report.json -k /tmp/kscan_results.json

# Export JSON for pipeline processing
./linx -l report.json -k kscan.json -j -o /tmp/correlation

# Quick assessment
./linx -l report.json
```

---

## Correlation Rules

| Rule | Severity | Condition | Composite |
|------|----------|-----------|-----------|
| Kernel Pointer Restriction | HIGH | kptr_restrict < 2 | No |
| Ptrace Scope | HIGH | ptrace_scope < 1 | No |
| ASLR Weak | HIGH | ASLR < 2 | No |
| dmesg Restricted | MEDIUM | dmesg_restrict < 1 | No |
| Unprivileged BPF | HIGH | unpriv_bpf != 1 | No |
| Kexec Enabled | MEDIUM | kexec_disabled != 1 | No |
| Perf Unrestricted | MEDIUM | perf_event_paranoid < 2 | No |
| User Namespaces | MEDIUM | userns_clone != 0 | No |
| KASLR Bypass Chain | CRITICAL | kptr_restrict < 2 AND ASLR < 2 | Yes |
| Address Disclosure Chain | HIGH | dmesg_restrict < 1 AND kptr_restrict < 2 | Yes |
| Multiple Kernel Failures | HIGH | 3+ kernel category VULN | Yes |
| RWX Memory Detected | HIGH/CRITICAL | K-Scanner confidence >= MEDIUM | No |

---

## Reports

| Format | File | Content |
|--------|------|---------|
| JSON | `correlation_report.json` | Machine-readable with findings, severity, sources, PIDs, recommendations |

---

## The Forensic Ecosystem

LinX is the correlation layer in the SYNTROPY forensic pipeline:

```
Phase 0: LinX (Correlate)  --> correlation_report.json
Phase 1: LinSpec (Audit)             --> report.json
Phase 2: S.I.R.E.N (Acquire)        --> memory dump + SHA256
Phase 3: K-Scanner (Analyze)         --> RWX detection + YARA
```

---

## Roadmap

- [x] High-performance C99 Core Engine
- [x] LinSpec JSON Report Parser
- [x] K-Scanner JSON Results Parser
- [x] Single-Check Correlation Rules (8 rules)
- [x] Composite Cross-Check Rules (2 rules)
- [x] K-Scanner Memory Alert Integration
- [x] JSON Export with Severity Classification
- [x] Minimal JSON Parser (zero dependencies)
- [x] Docker Container Image

---

## Build

```bash
make              # production build (stripped, hardened)
make debug        # debug build with symbols
make test         # run test suite
make lint         # static analysis (cppcheck + clang)
make docker       # build Docker image
make install      # install to /usr/local/bin
```

---

## Repository Structure

```text
├── docs/
│   ├── architecture.md
│   ├── correlation_rules.md
│   └── threat_model.md
├── include/
│   └── correlate.h
├── man/
│   └── linx.1
├── scripts/
│   └── install.sh
├── src/
│   ├── main.c
│   ├── correlate.c
│   └── report.c
├── tests/
│   └── run_tests.sh
├── Dockerfile
├── LICENSE
├── Makefile
├── SECURITY.md
└── README.md
```

---

## Security

- Input parsing rejects malformed JSON
- No `system()` or `popen()` calls
- Read-only analysis — no system state modification
- Binary built with PIE, RELRO, NOW, no-exec stack, `_FORTIFY_SOURCE=2`, stack protector

[![Docs-Security](https://img.shields.io/badge/Security-Policy-CC0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](SECURITY.md)

---

## Documentation

[![Docs-Architecture](https://img.shields.io/badge/Architecture-Design-00599C?style=flat-square&logo=linux&logoColor=white)](docs/architecture.md)
[![Docs-Rules](https://img.shields.io/badge/Correlation-Rules-8A2BE2?style=flat-square)](docs/correlation_rules.md)
[![Docs-ThreatModel](https://img.shields.io/badge/Threat-Model-CC0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](docs/threat_model.md)
