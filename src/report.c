#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "correlate.h"

static const char *severity_str(severity_t s)
{
    switch (s) {
        case SEV_INFO:     return "INFO";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "UNKNOWN";
    }
}

static const char *severity_color(severity_t s)
{
    switch (s) {
        case SEV_INFO:     return BLU;
        case SEV_LOW:      return GRN;
        case SEV_MEDIUM:   return YEL;
        case SEV_HIGH:     return RED;
        case SEV_CRITICAL: return RED BOLD;
        default:           return RESET;
    }
}

static void json_escape(FILE *f, const char *s)
{
    fputc('"', f);
    while (*s) {
        switch (*s) {
            case '"':  fprintf(f, "\\\""); break;
            case '\\': fprintf(f, "\\\\"); break;
            case '\n': fprintf(f, "\\n");  break;
            case '\r': fprintf(f, "\\r");  break;
            case '\t': fprintf(f, "\\t");  break;
            default:   fputc(*s, f);       break;
        }
        s++;
    }
    fputc('"', f);
}

int print_report(ctx_t *ctx)
{
    if (ctx->finding_count == 0) {
        printf("\n  " GRN "◆" RESET " No correlation findings. System posture is consistent.\n");
        return 0;
    }

    printf("\n  " BOLD "Correlation Findings:" RESET " %d total\n\n", ctx->finding_count);

    for (int i = 0; i < ctx->finding_count; i++) {
        finding_t *f = &ctx->findings[i];
        printf("  %s[%s]%s %s\n",
               severity_color(f->severity),
               severity_str(f->severity),
               RESET,
               f->title);
        printf("       %s%s%s\n", YEL, f->detail, RESET);
        if (f->related_pid > 0) {
            printf("       PID: %d | Source: %s\n", f->related_pid, f->source);
        } else {
            printf("       Source: %s\n", f->source);
        }
        if (strlen(f->related_check) > 0) {
            printf("       Check: %s\n", f->related_check);
        }
        if (strlen(f->recommendation) > 0) {
            printf("       " BOLD "Fix:" RESET " %s\n", f->recommendation);
        }
        printf("\n");
    }

    printf("\n  " CYN "─── Summary ─────────────────────────────────────────────────────" RESET "\n");
    printf("  %-30s %d\n", "LinSpec checks evaluated", ctx->checks_total);
    printf("  %-30s %d\n", "K-Scanner records loaded", ctx->kscanner_count);
    printf("  %-30s %d\n", "Correlation findings", ctx->finding_count);

    int high_crit = 0;
    for (int i = 0; i < ctx->finding_count; i++) {
        if (ctx->findings[i].severity >= SEV_HIGH) high_crit++;
    }
    if (high_crit > 0) {
        printf("\n  " RED "%d finding(s) require immediate attention." RESET "\n", high_crit);
    } else {
        printf("\n  " GRN "No critical findings." RESET "\n");
    }

    return 0;
}

static int has_path_traversal(const char *path)
{
    return strstr(path, "..") != NULL;
}

int export_json(ctx_t *ctx, const char *outdir)
{
    char dir[256] = "reports";
    if (outdir) {
        if (has_path_traversal(outdir)) {
            fprintf(stderr, "Error: path traversal detected in output directory.\n");
            return -1;
        }
        snprintf(dir, sizeof(dir), "%s", outdir);
    }

    mkdir(dir, 0755);

    char path[512];
    snprintf(path, sizeof(path), "%s/correlation_report.json", dir);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "{\n");
    fprintf(f, "  \"tool\": \"LinX\",\n");

    fprintf(f, "  \"hostname\": ");
    json_escape(f, ctx->hostname);
    fprintf(f, ",\n");
    fprintf(f, "  \"kernel\": ");
    json_escape(f, ctx->kernel);
    fprintf(f, ",\n");
    fprintf(f, "  \"timestamp\": ");
    json_escape(f, ctx->timestamp);
    fprintf(f, ",\n");
    fprintf(f, "  \"linspec_summary\": {\n");
    fprintf(f, "    \"total\": %d,\n", ctx->checks_total);
    fprintf(f, "    \"pass\": %d,\n", ctx->checks_pass);
    fprintf(f, "    \"warn\": %d,\n", ctx->checks_warn);
    fprintf(f, "    \"vuln\": %d\n", ctx->checks_vuln);
    fprintf(f, "  },\n");
    fprintf(f, "  \"kscanner_count\": %d,\n", ctx->kscanner_count);
    fprintf(f, "  \"findings_count\": %d,\n", ctx->finding_count);
    fprintf(f, "  \"findings\": [\n");

    for (int i = 0; i < ctx->finding_count; i++) {
        finding_t *ff = &ctx->findings[i];
        if (i > 0) fprintf(f, ",\n");
        fprintf(f, "    {\n");
        fprintf(f, "      \"severity\": ");
        json_escape(f, severity_str(ff->severity));
        fprintf(f, ",\n");
        fprintf(f, "      \"title\": ");
        json_escape(f, ff->title);
        fprintf(f, ",\n");
        fprintf(f, "      \"detail\": ");
        json_escape(f, ff->detail);
        fprintf(f, ",\n");
        fprintf(f, "      \"source\": ");
        json_escape(f, ff->source);
        fprintf(f, ",\n");
        fprintf(f, "      \"related_check\": ");
        json_escape(f, ff->related_check);
        fprintf(f, ",\n");
        fprintf(f, "      \"related_pid\": %d,\n", ff->related_pid);
        fprintf(f, "      \"recommendation\": ");
        json_escape(f, ff->recommendation);
        fprintf(f, "\n");
        fprintf(f, "    }");
    }

    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    return 0;
}
