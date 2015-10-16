#include "clee.h"

int clee_start(const char *filename, char *const argv[], char *const envp[]) {
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            /* error */
            return 0;
        case 0:
            ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
            execve(filename, argv, envp);   // causes SIGTRAP
            /* error */
            return 0;
        default: ;
            /* parent */
            int status;
            waitpid(pid, &status, 0);
            return WIFSTOPPED(status);  // success if child was stopped
    }
}
