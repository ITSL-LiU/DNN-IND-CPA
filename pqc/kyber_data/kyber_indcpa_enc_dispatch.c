#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>

/* kyber_indcpa_enc is a thin dispatcher, not a crypto binary itself.
 *
 * KYBER_K (and with it ETA1, the noise parameter that actually
 * distinguishes Kyber512/768/1024) is a *compile-time* constant in the
 * reference implementation -- a single binary can't select it at
 * runtime. So each param_set is built as its own correctly-parameterized
 * binary (kyber_indcpa_enc_512/768/1024, see the Makefile), and this
 * dispatcher just execs the one matching argv[1], preserving the
 * original single-binary "kyber_indcpa_enc <param_set> ..." interface
 * that data_generation.py already calls. */

int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        printf("Usage: %s <param_set> [N] [output_file]\n", argv[0]);
        printf("  param_set must be 512, 768, or 1024; dispatches to the\n");
        printf("  correspondingly-built kyber_indcpa_enc_<param_set> binary.\n");
        return (argc < 2) ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    int param_set = atoi(argv[1]);
    if (param_set != 512 && param_set != 768 && param_set != 1024) {
        fprintf(stderr, "Error: param_set must be 512, 768, or 1024\n");
        return EXIT_FAILURE;
    }

    char self_path[4096];
    strncpy(self_path, argv[0], sizeof(self_path) - 1);
    self_path[sizeof(self_path) - 1] = '\0';
    char *dir = dirname(self_path);

    char target[4096];
    snprintf(target, sizeof(target), "%s/kyber_indcpa_enc_%d", dir, param_set);

    execv(target, argv);

    // execv only returns on failure
    fprintf(stderr, "Error: could not run %s: %s\n", target, strerror(errno));
    return EXIT_FAILURE;
}
