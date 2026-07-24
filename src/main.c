#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "correlate.h"

static void print_usage(void)
{
    printf(CYN "╭─── LinX ────────────────────────────────────────────────────────────╮\n" RESET);
    printf(CYN "│" RESET "  " BOLD "Forensic Correlation Engine" RESET "  " CYN "                               │\n" RESET);
    printf(CYN "│" RESET "  " BOLD "Usage:" RESET " linx [options]" CYN "                                        │\n" RESET);
    printf(CYN "│" RESET "                                                               " CYN "│\n" RESET);
    printf(CYN "│" RESET "  -l, --linspec FILE   LinSpec report.json path               " CYN "│\n" RESET);
    printf(CYN "│" RESET "  -k, --kscanner FILE  K-Scanner results.json path            " CYN "│\n" RESET);
    printf(CYN "│" RESET "  -j, --json           Export JSON correlation report         " CYN "│\n" RESET);
    printf(CYN "│" RESET "  -o, --output-dir DIR Output directory (default: reports/)   " CYN "│\n" RESET);
    printf(CYN "│" RESET "  -V, --version        Show version                           " CYN "│\n" RESET);
    printf(CYN "│" RESET "  -h, --help           Show this help                         " CYN "│\n" RESET);
    printf(CYN "╰─────────────────────────────────────────────────────────────────────╯\n" RESET);
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    const char *linspec_path = NULL;
    const char *kscanner_path = NULL;
    const char *output_dir = NULL;
    int flag_json = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--linspec") == 0) {
            if (i + 1 < argc) linspec_path = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kscanner") == 0) {
            if (i + 1 < argc) kscanner_path = argv[++i];
        } else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            flag_json = 1;
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output-dir") == 0) {
            if (i + 1 < argc) output_dir = argv[++i];
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("LinX\n");
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage();
            return 1;
        }
    }

    if (!linspec_path && !kscanner_path) {
        fprintf(stderr, "  " RED "x" RESET " At least one of --linspec or --kscanner is required.\n");
        print_usage();
        return 1;
    }

    ctx_t ctx;
    ctx_init(&ctx);

    printf(CYN "╭─── LinX ────────────────────────────────────────────────────────────╮\n" RESET);
    printf(CYN "│" RESET "                     " BOLD "Forensic Correlation Engine" RESET "                     " CYN "│\n" RESET);
    printf(CYN "│" RESET "                        linux security fusion                        " CYN "│\n" RESET);
    printf(CYN "╰─────────────────────────────────────────────────────────────────────╯\n" RESET);

    if (linspec_path) {
        if (parse_linspec_file(&ctx, linspec_path) != 0) {
            fprintf(stderr, "  " RED "x" RESET " Failed to parse LinSpec report: %s\n", linspec_path);
            return 1;
        }
        printf("  " GRN "◆" RESET " LinSpec report loaded  (%d checks, %d VULN)\n",
               ctx.checks_total, ctx.checks_vuln);
    }

    if (kscanner_path) {
        if (parse_kscanner_file(&ctx, kscanner_path) != 0) {
            fprintf(stderr, "  " RED "x" RESET " Failed to parse K-Scanner results: %s\n", kscanner_path);
            return 1;
        }
        printf("  " GRN "◆" RESET " K-Scanner results loaded  (%d records)\n",
               ctx.kscanner_count);
    }

    printf(CYN "\n╭─── Correlation Analysis ────────────────────────────────────────────╮\n" RESET);
    run_correlation(&ctx);
    print_report(&ctx);

    if (flag_json) {
        if (export_json(&ctx, output_dir) == 0) {
            printf("\n  " GRN "◆" RESET " JSON correlation report generated\n");
        }
    }

    return 0;
}
