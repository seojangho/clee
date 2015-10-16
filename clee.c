#include "clee.h"

static pid_t tracee;

int clee_start(const char *filename, char *const argv[], char *const envp[]) {
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            /* error */
            return 0;
        case 0:
            if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) == -1)
            {
                /* ptrace error */
                _exit(1);
            }
            execve(filename, argv, envp);   // causes SIGTRAP
            /* execve error */
            _exit(1);
        default:
            /* parent */
            tracee = pid;
            int status;
            if (waitpid(pid, &status, 0) == -1)
            {
                /* waitpid error */
                return 0;
            }
            return WIFSTOPPED(status);  // fail on child ptrace/execve error
            if (WIFSTOPPED(status)) {
                clee_status(stopped, status);
                return 1;
            }
            else
            {
                return 0;
            }
    }
}

void clee_status(clee_tracee_status tracee_status, int status) {
}
