# Correlation Rules

## Overview

LinX applies a fixed set of correlation rules against LinSpec and K-Scanner outputs. Rules are evaluated in order and produce findings with severity classification.

---

## Rule Categories

### 1. Single-Check Rules (LinSpec)

These rules fire when a specific LinSpec check is VULN or WARN.

| Rule ID | LinSpec Check | Condition | Severity |
|---------|--------------|-----------|----------|
| kptr_restrict | kernel.kptr_restrict | < 2 | HIGH |
| ptrace_scope | kernel.yama.ptrace_scope | < 1 | HIGH |
| aslr_weak | kernel.randomize_va_space | < 2 | HIGH |
| dmesg_leak | kernel.dmesg_restrict | < 1 | MEDIUM |
| bpf_unpriv | kernel.unprivileged_bpf_disabled | != 1 | HIGH |
| kexec_enabled | kernel.kexec_disabled | != 1 | MEDIUM |
| perf_unrestricted | kernel.perf_event_paranoid | < 2 | MEDIUM |
| userns_enabled | kernel.userns_restrict | != 1 | MEDIUM |

### 2. Composite Rules (LinSpec + LinSpec)

These rules fire when multiple LinSpec checks are simultaneously VULN.

| Rule ID | Conditions | Severity | Rationale |
|---------|------------|----------|-----------|
| kaslr_bypass | kptr_restrict < 2 AND ASLR < 2 | CRITICAL | KASLR bypass chain complete: kernel base address readable + no address randomization |
| addr_disclosure | dmesg_restrict < 1 AND kptr_restrict < 2 | HIGH | Multiple kernel address leak paths available simultaneously |
| multi_kernel_fail | 3+ kernel category checks VULN | HIGH | Widespread kernel protection failure |

### 3. Memory Rules (K-Scanner)

| Rule ID | Condition | Severity |
|---------|-----------|----------|
| rwx_detected | K-Scanner confidence >= MEDIUM | HIGH |
| rwx_critical | K-Scanner confidence == CRITICAL | CRITICAL |

---

## Severity Classification

| Severity | Color | Meaning |
|----------|-------|---------|
| INFO | Blue | Informational, no immediate risk |
| LOW | Green | Minor misconfiguration, limited exploit value |
| MEDIUM | Yellow | Notable weakness, requires attention |
| HIGH | Red | Significant vulnerability, active risk |
| CRITICAL | Red bold | Immediate threat, exploitation likely |

---

## Adding New Rules

Rules are defined as a static table in `correlate.c`:

```c
static const rule_def_t rules[] = {
    {"check_name", threshold, SEV_HIGH,
     "Title",
     "Detailed description.",
     "Recommendation"}
};
```

Composite rules are implemented as separate logic blocks in `run_correlation()`.
