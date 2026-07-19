# Architecture

## Overview

LinX is a minimal C99 correlation engine that connects LinSpec's kernel hardening audit with K-Scanner's memory analysis. It is the correlation layer in the SYNTROPY forensic ecosystem — lightweight, dependency-free, and focused on deterministic cross-referencing.

---

## Components

### main.c

Entry point. Parses CLI flags with getopt-style string comparison. Loads LinSpec and/or K-Scanner JSON files, dispatches correlation, and produces output.

### correlate.c

Core engine. Contains:
- **Minimal JSON parser**: Recursive descent parser handling objects, arrays, strings, and numbers. Targets the known LinSpec and K-Scanner output formats.
- **LinSpec report parser**: Extracts per-check name, result (PASS/WARN/VULN), category, current/expected values from report.json
- **K-Scanner results parser**: Extracts PID, process name, and confidence level from JSON array
- **Correlation rule table**: 8 single-check rules, 2 composite rules, 1 memory analysis rule. Each rule defines severity, condition, title, and recommendation.
- **Correlation engine**: Iterates rules against parsed data, produces findings with severity classification.

### report.c

Output generators. Contains:
- **Terminal report**: ANSI-colored findings grouped by severity, with detail and recommendations
- **JSON report**: Machine-readable output with full finding metadata for pipeline integration

### correlate.h

Type definitions: ctx_t (correlation context), linspec_check_t, kscanner_rec_t, finding_t, severity_t. Function declarations for all public APIs.

---

## Data Flow

```
CLI (main.c)
  |
  +---> parse_linspec_file()  --> ctx->linspec_checks[]
  +---> parse_kscanner_file() --> ctx->kscanner_recs[]
  |
  v
run_correlation()
  |
  +---> For each rule in table:
  |       |---> find_check(name)
  |       |---> evaluate condition
  |       |---> add_finding() if triggered
  |
  +---> Composite rules (KASLR chain, address disclosure)
  +---> K-Scanner RWX rules
  |
  v
print_report() / export_json()
  |
  +---> Terminal UI (ANSI colored)
  +---> JSON report (correlation_report.json)
```

---

## Data Sources

- **LinSpec report.json**: Per-check results with name, result (PASS/WARN/VULN), category, current value, expected value
- **K-Scanner results JSON**: Array of records with pid, process, confidence (SAFE/LOW/MEDIUM/CRITICAL)

---

## Design Principles

- **Zero dependencies**: Pure C99 with standard libc only
- **Forensic safety**: Read-only analysis — no kernel or process state modification
- **Deterministic evaluation**: Fixed rule baseline, reproducible results
- **Minimal scope**: 3 source files, focused on correlation alone

---

## The Correlation Contract

The main architectural output is `correlation_report.json`. It contains:
- Tool name and version
- Hostname, kernel, and timestamp from the source reports
- LinSpec summary statistics
- Per-finding severity, title, detail, source, related check/PID, recommendation
