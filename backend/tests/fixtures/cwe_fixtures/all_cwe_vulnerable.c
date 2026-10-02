/*
 * CHAKRAVYUH CWE Test Fixtures
 * Intentionally vulnerable C programs for all 21 supported CWEs.
 *
 * IMPORTANT: These files are FOR TESTING ONLY.
 * They are intentionally vulnerable and must NEVER be deployed.
 *
 * Each CWE section contains:
 *   - Vulnerable function
 *   - Safe wrapper / main
 *   - Comments showing: trigger, expected CWE, verification method, expected patch
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>

/* ============================================================
 * CWE-120: Buffer Overflow (Classic)
 * Trigger: input > 63 bytes
 * Verification: asan_runtime
 * Expected patch: strnlen + bounds check before copy
 * ============================================================ */
void cwe120_vulnerable(const char *input) {
    char buf[64];
    strcpy(buf, input);  /* VULN: no bounds check */
    printf("CWE-120: %s\n", buf);
}

/* ============================================================
 * CWE-122: Heap Buffer Overflow
 * Trigger: input > 63 bytes to heap buffer
 * Verification: asan_runtime
 * Expected patch: snprintf with sizeof() bound
 * ============================================================ */
void cwe122_vulnerable(const char *input) {
    char *buf = malloc(64);
    if (!buf) return;
    strcpy(buf, input);  /* VULN: heap overflow */
    printf("CWE-122: %s\n", buf);
    free(buf);
}

/* ============================================================
 * CWE-125: Out-of-Bounds Read
 * Trigger: index >= 10
 * Verification: asan_runtime
 * Expected patch: index bounds check before array access
 * ============================================================ */
int cwe125_vulnerable(int index) {
    int arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    return arr[index];  /* VULN: no bounds check */
}

/* ============================================================
 * CWE-787: Out-of-Bounds Write
 * Trigger: index >= 10 with write
 * Verification: asan_runtime
 * Expected patch: bounds check before write
 * ============================================================ */
void cwe787_vulnerable(int index, int value) {
    int arr[10] = {0};
    arr[index] = value;  /* VULN: out-of-bounds write */
}

/* ============================================================
 * CWE-416: Use-After-Free
 * Trigger: any input (follows free path)
 * Verification: asan_runtime
 * Expected patch: ptr = NULL after free
 * ============================================================ */
void cwe416_vulnerable(int trigger) {
    char *ptr = malloc(32);
    if (!ptr) return;
    snprintf(ptr, 32, "data");
    if (trigger) {
        free(ptr);
        /* VULN: access after free */
        printf("CWE-416: %s\n", ptr);
    }
}

/* ============================================================
 * CWE-415: Double Free
 * Trigger: any input
 * Verification: asan_runtime
 * Expected patch: ptr = NULL after first free
 * ============================================================ */
void cwe415_vulnerable(int trigger) {
    char *ptr = malloc(32);
    if (!ptr) return;
    free(ptr);
    if (trigger) {
        free(ptr);  /* VULN: double free */
    }
}

/* ============================================================
 * CWE-476: NULL Pointer Dereference
 * Trigger: pass NULL or 0
 * Verification: ubsan_runtime
 * Expected patch: null check before dereference
 * ============================================================ */
struct node { int value; struct node *next; };
int cwe476_vulnerable(struct node *n) {
    return n->value;  /* VULN: no null check */
}

/* ============================================================
 * CWE-843: Type Confusion
 * Trigger: negative or out-of-range type tag
 * Verification: ubsan_runtime
 * Expected patch: type field validation
 * ============================================================ */
typedef union {
    int as_int;
    float as_float;
    char *as_str;
} confused_t;

int cwe843_vulnerable(int type_tag, confused_t val) {
    if (type_tag == 1) return val.as_int;
    if (type_tag == 2) return (int)val.as_float;
    /* VULN: type_tag not validated — out-of-range causes confusion */
    return (int)(uintptr_t)val.as_str;
}

/* ============================================================
 * CWE-190: Integer Overflow
 * Trigger: a * b overflows (e.g. a=2147483647, b=2)
 * Verification: ubsan_runtime
 * Expected patch: overflow check before multiply
 * ============================================================ */
size_t cwe190_vulnerable(size_t a, size_t b) {
    return a * b;  /* VULN: no overflow check */
}

/* ============================================================
 * CWE-191: Integer Underflow
 * Trigger: a=0, b=1 → underflow in unsigned subtract
 * Verification: ubsan_runtime
 * Expected patch: guard a >= b before subtraction
 * ============================================================ */
size_t cwe191_vulnerable(size_t a, size_t b) {
    return a - b;  /* VULN: unsigned underflow */
}

/* ============================================================
 * CWE-369: Divide by Zero
 * Trigger: b=0
 * Verification: ubsan_runtime (SIGFPE)
 * Expected patch: if (b == 0) return -1;
 * ============================================================ */
int cwe369_vulnerable(int a, int b) {
    return a / b;  /* VULN: no zero check */
}

/* ============================================================
 * CWE-20: Improper Input Validation
 * Trigger: negative value or very large value
 * Verification: injection_sandbox
 * Expected patch: bounds check on input value
 * ============================================================ */
void cwe20_vulnerable(int user_value) {
    /* VULN: no validation of user_value */
    char buf[user_value];  /* VLA with unchecked user value */
    snprintf(buf, user_value, "processed: %d", user_value);
    printf("%s\n", buf);
}

/* ============================================================
 * CWE-134: Format String
 * Trigger: input containing %x, %n, %s specifiers
 * Verification: injection_sandbox
 * Expected patch: printf("%s", user_input)
 * ============================================================ */
void cwe134_vulnerable(const char *user_input) {
    printf(user_input);  /* VULN: user input as format string */
}

/* ============================================================
 * CWE-78: OS Command Injection
 * Trigger: input containing shell metacharacters
 * Verification: injection_sandbox (harmless markers only)
 * Expected patch: execv() or validated allowlist
 * ============================================================ */
void cwe78_vulnerable(const char *user_input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "echo %s", user_input);
    system(cmd);  /* VULN: user input interpolated into shell command */
}

/* ============================================================
 * CWE-22: Path Traversal
 * Trigger: ../../../etc/passwd style input
 * Verification: injection_sandbox (synthetic filesystem)
 * Expected patch: realpath() + directory prefix check
 * ============================================================ */
void cwe22_vulnerable(const char *user_path) {
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/var/www/files/%s", user_path);
    FILE *f = fopen(full_path, "r");  /* VULN: no path canonicalization */
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) printf("%s", line);
        fclose(f);
    }
}

/* ============================================================
 * CWE-362: Race Condition
 * Trigger: concurrent access to shared counter
 * Verification: tsan_concurrency
 * Expected patch: mutex around counter update
 * ============================================================ */
static int shared_counter = 0;
void cwe362_vulnerable(void) {
    /* VULN: no synchronization on shared_counter */
    shared_counter++;
}

/* ============================================================
 * CWE-367: TOCTOU (Time-of-Check to Time-of-Use)
 * Trigger: race between access() check and open()
 * Verification: tsan_concurrency
 * Expected patch: open() with O_NOFOLLOW, then fstat on fd
 * ============================================================ */
int cwe367_vulnerable(const char *path) {
    if (access(path, R_OK) == 0) {  /* CHECK */
        /* VULN: window between check and use */
        return open(path, O_RDONLY);  /* USE */
    }
    return -1;
}

/* ============================================================
 * CWE-327: Weak Cryptography
 * Trigger: static analysis (MD5 usage detected)
 * Verification: static_ast
 * Expected patch: replace with SHA-256
 * ============================================================ */
#ifdef USE_OPENSSL
#include <openssl/md5.h>
void cwe327_vulnerable(const unsigned char *data, size_t len, unsigned char *digest) {
    MD5(data, len, digest);  /* VULN: MD5 is cryptographically broken */
}
#else
void cwe327_vulnerable(const unsigned char *data, size_t len, unsigned char *digest) {
    /* Mock for testing without OpenSSL */
    (void)data; (void)len; (void)digest;
    printf("MD5_hash_computed\n");  /* VULN marker */
}
#endif

/* ============================================================
 * CWE-321: Hardcoded Cryptographic Key
 * Trigger: static analysis (hardcoded key bytes)
 * Verification: static_ast
 * Expected patch: load from environment variable
 * ============================================================ */
static const unsigned char hardcoded_key[] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,  /* VULN: hardcoded AES key */
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50
};

const unsigned char *cwe321_get_key(void) {
    return hardcoded_key;  /* VULN: returns hardcoded key */
}

/* ============================================================
 * CWE-798: Hardcoded Credentials
 * Trigger: static analysis (hardcoded password comparison)
 * Verification: static_ast
 * Expected patch: load from getenv()
 * ============================================================ */
int cwe798_authenticate(const char *password) {
    const char *expected = "admin123secret";  /* VULN: hardcoded credential */
    return strcmp(password, expected) == 0;
}

/* ============================================================
 * CWE-400: Resource Exhaustion
 * Trigger: large user_size value
 * Verification: resource_monitor
 * Expected patch: size limit + malloc guard
 * ============================================================ */
void *cwe400_vulnerable(size_t user_size) {
    void *buf = malloc(user_size);  /* VULN: unbounded allocation */
    if (!buf) return NULL;
    memset(buf, 0, user_size);      /* VULN: fills entire unbounded allocation */
    return buf;
}

/* ============================================================
 * Main dispatcher for testing
 * ============================================================ */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cwe_number> [input]\n", argv[0]);
        return 1;
    }

    int cwe_num = atoi(argv[1]);
    const char *input = argc > 2 ? argv[2] : "test_input";
    int int_input = argc > 2 ? atoi(argv[2]) : 42;

    switch (cwe_num) {
        case 120: cwe120_vulnerable(input); break;
        case 122: cwe122_vulnerable(input); break;
        case 125: printf("%d\n", cwe125_vulnerable(int_input)); break;
        case 787: cwe787_vulnerable(int_input, 99); break;
        case 416: cwe416_vulnerable(1); break;
        case 415: cwe415_vulnerable(1); break;
        case 476: {
            struct node *n = int_input == 0 ? NULL : &(struct node){int_input, NULL};
            printf("%d\n", cwe476_vulnerable(n));
            break;
        }
        case 843: {
            confused_t v; v.as_int = int_input;
            printf("%d\n", cwe843_vulnerable(int_input, v));
            break;
        }
        case 190: printf("%zu\n", cwe190_vulnerable((size_t)int_input, 2000000)); break;
        case 191: printf("%zu\n", cwe191_vulnerable(0, (size_t)int_input)); break;
        case 369: printf("%d\n", cwe369_vulnerable(100, int_input)); break;
        case 20: cwe20_vulnerable(int_input); break;
        case 134: cwe134_vulnerable(input); break;
        case 78: cwe78_vulnerable(input); break;
        case 22: cwe22_vulnerable(input); break;
        case 362: cwe362_vulnerable(); break;
        case 367: printf("%d\n", cwe367_vulnerable(input)); break;
        case 327: cwe327_vulnerable((const unsigned char*)input, strlen(input), NULL); break;
        case 321: printf("key=%p\n", (void*)cwe321_get_key()); break;
        case 798: printf("auth=%d\n", cwe798_authenticate(input)); break;
        case 400: {
            void *buf = cwe400_vulnerable((size_t)int_input);
            printf("allocated %p\n", buf);
            free(buf);
            break;
        }
        default:
            fprintf(stderr, "Unknown CWE: %d\n", cwe_num);
            return 1;
    }

    return 0;
}
