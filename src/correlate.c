#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "correlate.h"

void ctx_init(ctx_t *ctx)
{
    memset(ctx, 0, sizeof(ctx_t));
}

static int file_read(const char *path, char **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "  " RED "x" RESET " Cannot open file: %s\n", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "  " RED "x" RESET " Cannot seek file: %s\n", path);
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fprintf(stderr, "  " RED "x" RESET " Cannot determine file size: %s\n", path);
        fclose(f);
        return -1;
    }
    if (sz == 0) {
        fprintf(stderr, "  " RED "x" RESET " File is empty: %s\n", path);
        fclose(f);
        return -1;
    }
    rewind(f);
    *out = malloc((size_t)sz + 1);
    if (!*out) {
        fprintf(stderr, "  " RED "x" RESET " Out of memory reading: %s\n", path);
        fclose(f);
        return -1;
    }
    *out_len = fread(*out, 1, (size_t)sz, f);
    if (*out_len == 0 && sz > 0) {
        fprintf(stderr, "  " RED "x" RESET " Read error: %s\n", path);
        free(*out); *out = NULL; fclose(f);
        return -1;
    }
    fclose(f);
    (*out)[*out_len] = '\0';
    return 0;
}

static const char *json_skip(const char *p)
{
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

static const char *json_string(const char *p, char *out, size_t max)
{
    p = json_skip(p);
    if (*p != '"') return NULL;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < max - 1) {
        if (*p == '\\' && *(p + 1)) { p++; out[i++] = *p++; }
        else { out[i++] = *p++; }
    }
    out[i] = '\0';
    if (*p == '"') p++;
    return p;
}

static const char *json_number(const char *p, int *out)
{
    p = json_skip(p);
    *out = 0;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    while (*p >= '0' && *p <= '9') {
        *out = *out * 10 + (*p - '0');
        p++;
    }
    if (neg) *out = -*out;
    return p;
}

static const char *json_skip_value(const char *p)
{
    p = json_skip(p);
    if (*p == '{' || *p == '[') {
        p++;
        int depth = 1;
        while (*p && depth > 0) {
            if (*p == '{' || *p == '[') depth++;
            else if (*p == '}' || *p == ']') depth--;
            if (depth > 0) p++;
        }
        if (*p) p++;
    } else if (*p == '"') {
        p++;
        while (*p) {
            if (*p == '\\' && *(p + 1)) {
                p += 2;
            } else if (*p == '"') {
                p++;
                break;
            } else {
                p++;
            }
        }
        if (*p) p++;
    } else {
        while (*p && *p != ',' && *p != '}' && *p != ']' && *p != '\n') p++;
    }
    return p;
}

static const char *json_find_key(const char *p, const char *key)
{
    p = json_skip(p);
    if (*p != '{') return NULL;
    p++;
    char k[256];
    while (*p && *p != '}') {
        p = json_skip(p);
        if (*p == '}') break;
        p = json_string(p, k, sizeof(k));
        if (!p) return NULL;
        p = json_skip(p);
        if (*p != ':') return NULL;
        p++;
        p = json_skip(p);
        if (strcmp(k, key) == 0) return p;
        p = json_skip_value(p);
        if (*p == ',') p++;
    }
    return NULL;
}

int parse_linspec_file(ctx_t *ctx, const char *path)
{
    char *data = NULL;
    size_t len = 0;
    if (file_read(path, &data, &len) != 0) return -1;

    const char *p = json_skip(data);
    if (*p != '{') {
        fprintf(stderr, "  " RED "x" RESET " LinSpec report must be a JSON object (starts with '{')\n");
        free(data);
        return -1;
    }

    const char *root = p;
    const char *val;

    val = json_find_key(root, "hostname");
    if (val) {
        json_string(val, ctx->hostname, sizeof(ctx->hostname));
    }

    val = json_find_key(root, "kernel");
    if (val) {
        json_string(val, ctx->kernel, sizeof(ctx->kernel));
    }

    val = json_find_key(root, "timestamp");
    if (val) {
        json_string(val, ctx->timestamp, sizeof(ctx->timestamp));
    }

    p = json_find_key(root, "checks");
    if (!p) {
        fprintf(stderr, "  " RED "x" RESET " Missing 'checks' array in LinSpec report\n");
        free(data);
        return -1;
    }
    if (*p != '[') {
        fprintf(stderr, "  " RED "x" RESET " 'checks' must be a JSON array in LinSpec report\n");
        free(data);
        return -1;
    }
    p++;
    p = json_skip(p);

    while (*p && *p != ']' && ctx->linspec_count < MAX_LINSPEC_CHECKS) {
        if (*p == '{') {
            linspec_check_t *c = &ctx->linspec_checks[ctx->linspec_count];
            const char *obj = p;
            const char *kp;

            kp = json_find_key(obj, "name");
            if (kp) { kp = json_string(kp, c->name, sizeof(c->name)); }

            kp = json_find_key(obj, "result");
            if (!kp) kp = json_find_key(obj, "status");
            if (kp) { kp = json_string(kp, c->result, sizeof(c->result)); }

            kp = json_find_key(obj, "category");
            if (kp) { kp = json_string(kp, c->category, sizeof(c->category)); }

            kp = json_find_key(obj, "current");
            if (kp) { kp = json_number(kp, &c->current_val); }

            kp = json_find_key(obj, "expected");
            if (kp) { kp = json_number(kp, &c->expected_val); }

            c->found = 1;
            ctx->linspec_count++;
        }
        p = json_skip_value(p);
        if (*p == ',') p++;
        p = json_skip(p);
    }

    free(data);

    ctx->checks_total = ctx->linspec_count;
    for (int i = 0; i < ctx->linspec_count; i++) {
        if (strcmp(ctx->linspec_checks[i].result, "VULN") == 0) ctx->checks_vuln++;
        else if (strcmp(ctx->linspec_checks[i].result, "WARN") == 0) ctx->checks_warn++;
        else if (strcmp(ctx->linspec_checks[i].result, "PASS") == 0) ctx->checks_pass++;
    }

    if (ctx->linspec_count == 0) {
        fprintf(stderr, "  " YEL "!" RESET " No checks found in LinSpec report (empty array?)\n");
    }

    return 0;
}

int parse_kscanner_file(ctx_t *ctx, const char *path)
{
    char *data = NULL;
    size_t len = 0;
    if (file_read(path, &data, &len) != 0) return -1;

    const char *p = json_skip(data);
    if (*p != '[') {
        fprintf(stderr, "  " RED "x" RESET " K-Scanner results must be a JSON array (starts with '[')\n");
        free(data);
        return -1;
    }
    p++;
    p = json_skip(p);

    while (*p && *p != ']' && ctx->kscanner_count < MAX_KSCANNER_RECS) {
        if (*p == '{') {
            kscanner_rec_t *r = &ctx->kscanner_recs[ctx->kscanner_count];
            const char *obj = p;
            const char *kp;

            kp = json_find_key(obj, "pid");
            if (kp) { kp = json_number(kp, &r->pid); }

            kp = json_find_key(obj, "process");
            if (kp) { kp = json_string(kp, r->process, sizeof(r->process)); }

            kp = json_find_key(obj, "confidence");
            if (kp) { kp = json_string(kp, r->confidence, sizeof(r->confidence)); }

            if (r->pid > 0) {
                r->found = 1;
                ctx->kscanner_count++;
            }
        }
        p = json_skip_value(p);
        if (*p == ',') p++;
        p = json_skip(p);
    }

    free(data);

    if (ctx->kscanner_count == 0) {
        fprintf(stderr, "  " YEL "!" RESET " No records found in K-Scanner results (empty array?)\n");
    }

    return 0;
}

static linspec_check_t *find_check(ctx_t *ctx, const char *name)
{
    for (int i = 0; i < ctx->linspec_count; i++) {
        if (strcmp(ctx->linspec_checks[i].name, name) == 0)
            return &ctx->linspec_checks[i];
    }
    return NULL;
}

static void add_finding(ctx_t *ctx, severity_t sev, const char *title,
                        const char *detail, const char *source,
                        const char *check, int pid, const char *rec)
{
    if (ctx->finding_count >= MAX_FINDINGS) return;
    finding_t *f = &ctx->findings[ctx->finding_count++];
    f->severity = sev;
    snprintf(f->title, sizeof(f->title), "%s", title);
    snprintf(f->detail, sizeof(f->detail), "%s", detail);
    snprintf(f->source, sizeof(f->source), "%s", source);
    snprintf(f->related_check, sizeof(f->related_check), "%s", check);
    f->related_pid = pid;
    snprintf(f->recommendation, sizeof(f->recommendation), "%s", rec);
}

static int is_vuln(linspec_check_t *c)
{
    return c && c->found && (strcmp(c->result, "VULN") == 0 || strcmp(c->result, "WARN") == 0);
}

typedef struct {
    const char *check_name;
    int vuln_if_lt;
    severity_t severity;
    const char *title;
    const char *detail;
    const char *rec;
} rule_def_t;

static const rule_def_t rules[] = {
    {"kptr_restrict", 2, SEV_HIGH,
     "Kernel Pointer Restriction Disabled",
     "/proc/kallsyms is world-readable. KASLR base address exposed to unprivileged users.",
     "Set kernel.kptr_restrict=2 in sysctl.conf"},

    {"ptrace_scope", 1, SEV_HIGH,
     "Ptrace Scope Unrestricted",
     "Process injection via ptrace(2) is possible. Unprivileged users can attach to any process.",
     "Set kernel.yama.ptrace_scope=1 in sysctl.conf"},

    {"aslr", 2, SEV_HIGH,
     "ASLR Disabled or Weak",
     "Memory layout is predictable. Exploitation reliability increases significantly.",
     "Set kernel.randomize_va_space=2 in sysctl.conf"},

    {"dmesg_restrict", 1, SEV_MEDIUM,
     "Kernel dmesg Unrestricted",
     "Kernel ring buffer is readable by unprivileged users. Kernel addresses may leak.",
     "Set kernel.dmesg_restrict=1 in sysctl.conf"},

    {"unpriv_bpf", 0, SEV_HIGH,
     "Unprivileged BPF Enabled",
     "BPF is accessible to unprivileged users. Potential for Spectre v2 gadgets or information leaks.",
     "Set kernel.unprivileged_bpf_disabled=1 in sysctl.conf"},

    {"kexec_disabled", 1, SEV_MEDIUM,
     "Kexec Load Enabled",
     "Arbitrary kernel code loading is permitted via kexec.",
     "Set kernel.kexec_disabled=1 in sysctl.conf"},

    {"perf_event_paranoid", 2, SEV_MEDIUM,
     "Perf Event Monitoring Unrestricted",
     "Performance monitoring exposes hardware event data to unprivileged users.",
     "Set kernel.perf_event_paranoid=2 in sysctl.conf"},

    {"userns_clone", 0, SEV_MEDIUM,
     "User Namespaces Enabled",
     "User namespace creation is available. Increases kernel attack surface for privilege escalation.",
     "Set kernel.userns_restrict=1 or via appropriate sysctl"}
};

int run_correlation(ctx_t *ctx)
{
    int rule_count = sizeof(rules) / sizeof(rules[0]);

    for (int i = 0; i < rule_count; i++) {
        linspec_check_t *c = find_check(ctx, rules[i].check_name);
        if (is_vuln(c)) {
            if (rules[i].vuln_if_lt == 0 || c->current_val < rules[i].vuln_if_lt) {
                add_finding(ctx, rules[i].severity, rules[i].title,
                           rules[i].detail, "LinSpec", rules[i].check_name, 0, rules[i].rec);
            }
        }
    }

    for (int i = 0; i < ctx->kscanner_count; i++) {
        kscanner_rec_t *r = &ctx->kscanner_recs[i];
        if (!r->found) continue;

        int is_critical = (strcmp(r->confidence, "CRITICAL") == 0);
        int is_high = (strcmp(r->confidence, "MEDIUM") == 0 || is_critical);

        if (is_high) {
            char detail[256];
            snprintf(detail, sizeof(detail),
                     "PID %d (%s) has RWX memory regions (confidence: %s). "
                     "Possible shellcode injection or JIT activity.",
                     r->pid, r->process, r->confidence);
            char rec[256];
            snprintf(rec, sizeof(rec),
                     "Investigate PID %d (%s). Dump memory for further analysis.",
                     r->pid, r->process);
            add_finding(ctx, is_critical ? SEV_CRITICAL : SEV_HIGH,
                       "RWX Memory Region Detected",
                       detail, "K-Scanner", "", r->pid, rec);
        }
    }

    linspec_check_t *kptr = find_check(ctx, "kptr_restrict");
    linspec_check_t *aslr = find_check(ctx, "aslr");
    linspec_check_t *dmesg = find_check(ctx, "dmesg_restrict");

    if (is_vuln(kptr) && is_vuln(aslr)) {
        add_finding(ctx, SEV_CRITICAL,
                   "KASLR Bypass Chain Complete",
                   "Both kptr_restrict and ASLR are disabled. KASLR bypass prerequisites met: "
                   "kernel base address is readable and address space randomization is weak.",
                   "LinSpec", "kptr_restrict+aslr", 0,
                   "Set kernel.kptr_restrict=2 and kernel.randomize_va_space=2. Reboot.");
    }

    if (is_vuln(dmesg) && is_vuln(kptr)) {
        add_finding(ctx, SEV_HIGH,
                   "Kernel Address Disclosure Chain",
                   "Both dmesg_restrict and kptr_restrict are disabled. Multiple kernel "
                   "address leak paths are available.",
                   "LinSpec", "dmesg_restrict+kptr_restrict", 0,
                   "Restrict both kernel.dmesg_restrict and kernel.kptr_restrict.");
    }

    int vuln_kernel = 0;
    for (int i = 0; i < ctx->linspec_count; i++) {
        if (strcmp(ctx->linspec_checks[i].category, "kernel") == 0 &&
            is_vuln(&ctx->linspec_checks[i]))
            vuln_kernel++;
    }
    if (vuln_kernel >= 3) {
        add_finding(ctx, SEV_HIGH,
                   "Multiple Kernel Protections Disabled",
                   "Three or more kernel-level security checks are failing. "
                   "System is exposed to multiple attack vectors simultaneously.",
                   "LinSpec", "", 0,
                   "Review and remediate all VULN kernel checks. Prioritize kptr_restrict, ptrace_scope.");
    }

    return 0;
}
