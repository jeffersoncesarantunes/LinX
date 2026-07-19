# Threat Model

## Objective

Map attacker capabilities to correlated weaknesses detectable by LinX. Shows how individual misconfigurations compound into exploitable attack chains.

---

## Assumed Attacker Capabilities

- **Local Access:** Unprivileged shell access
- **Code Execution:** Can compile and run arbitrary binaries
- **Exploitation Knowledge:** Familiar with modern kernel exploitation techniques

---

## Attack Chains

### 1. KASLR Bypass + Exploitation

**Individual weaknesses:**
- kptr_restrict=0 → /proc/kallsyms exposes kernel base
- ASLR=0 → No address randomization

**Combined effect:** Attacker reads kernel base address from /proc/kallsyms, then crafts reliable exploit without guessing offsets. **CRITICAL.**

**LinX rule:** `kaslr_bypass`

### 2. Process Injection

**Individual weaknesses:**
- ptrace_scope=0 → Any process can ptrace any other
- K-Scanner detects RWX memory → Evidence of code injection

**Combined effect:** Attacker attaches to a process with RWX regions, injects shellcode, executes payload. **HIGH.**

**LinX rule:** Not yet implemented (requires both LinSpec + K-Scanner correlation).

### 3. Kernel Address Leak

**Individual weaknesses:**
- dmesg_restrict=0 → Kernel ring buffer world-readable
- kptr_restrict=0 → /proc/kallsyms world-readable

**Combined effect:** Multiple independent kernel address leak paths. Increases probability of successful KASLR bypass. **HIGH.**

**LinX rule:** `addr_disclosure`

### 4. Widespread Kernel Hardening Failure

**Individual weaknesses:**
- 3 or more kernel-category checks are VULN

**Combined effect:** System is missing multiple independent protections. Attackers have a broad attack surface. **HIGH.**

**LinX rule:** `multi_kernel_fail`

---

## Detection Gap Matrix

| Attack Chain | Individual Detection | Correlated Detection |
|-------------|---------------------|---------------------|
| KASLR bypass | LinSpec finds kptr_restrict=0 OR ASLR=0 | LinX finds both simultaneously |
| Process injection | LinSpec finds ptrace_scope=0, K-Scanner finds RWX | Manual cross-reference needed |
| Address leak | LinSpec finds dmesg_restrict=0 OR kptr_restrict=0 | LinX finds both |
| Broad failure | LinSpec finds multiple VULN | LinX counts kernel-category VULN |

---

## Limitations

- **No real-time monitoring**: LinX operates on point-in-time snapshots from LinSpec and K-Scanner
- **No log correlation**: Journalctl and auditd analysis are not yet implemented
- **Static rule set**: Rules are compiled into the binary and cannot be extended at runtime
