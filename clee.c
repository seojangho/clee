#include "clee.h"

int clee_start(const char *filename, char *const argv[], char *const envp[]) {
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            /* error */
            return 0;
        case 0:
            execve(filename, argv, envp);
            /* error */
            return 0;
        default:
            /* parent */
            return 1;
    }
}
