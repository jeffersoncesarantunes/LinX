#ifndef CORRELATE_H
#define CORRELATE_H

#define MAX_NAME 64
#define MAX_PATH 256
#define MAX_DESC 256
#define MAX_LINE 4096
#define MAX_FINDINGS 64
#define MAX_LINSPEC_CHECKS 64
#define MAX_KSCANNER_RECS 64
#define MAX_CHECK_NAME 48

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define BOLD  "\x1B[1m"
#define RESET "\x1B[0m"

typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} severity_t;

typedef struct {
    char name[MAX_CHECK_NAME];
    char result[16];
    char category[MAX_NAME];
    int current_val;
    int expected_val;
    int found;
} linspec_check_t;

typedef struct {
    int pid;
    char process[MAX_NAME];
    char confidence[16];
    int found;
} kscanner_rec_t;

typedef struct {
    severity_t severity;
    char title[MAX_DESC];
    char detail[MAX_DESC];
    char source[MAX_NAME];
    char related_check[MAX_CHECK_NAME];
    int related_pid;
    char recommendation[MAX_DESC];
} finding_t;

typedef struct {
    linspec_check_t linspec_checks[MAX_LINSPEC_CHECKS];
    int linspec_count;
    kscanner_rec_t kscanner_recs[MAX_KSCANNER_RECS];
    int kscanner_count;
    finding_t findings[MAX_FINDINGS];
    int finding_count;
    char hostname[MAX_NAME];
    char kernel[64];
    char timestamp[64];
    int checks_total;
    int checks_pass;
    int checks_warn;
    int checks_vuln;
} ctx_t;

int parse_linspec_file(ctx_t *ctx, const char *path);
int parse_kscanner_file(ctx_t *ctx, const char *path);
int run_correlation(ctx_t *ctx);
int export_json(ctx_t *ctx, const char *outdir);
int print_report(ctx_t *ctx);
void ctx_init(ctx_t *ctx);

#endif
