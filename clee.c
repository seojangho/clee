#include "clee.h"

static pid_t tracee;

void clee_init() {
    errno = 0;
    signal(SIGCHLD, clee_signal_chld);
    if (errno) {
        CLEE_ERROR;
    }
}

void clee_start(const char *filename, char *const argv[], char *const envp[]) {
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            /* error */
            CLEE_ERROR;
        case 0:
            if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) == -1)
            {
                /* ptrace error */
                CLEE_ERROR; /* FIXME CLEE_ERROR from child */
            }
            execve(filename, argv, envp);   // causes SIGTRAP
            /* execve error */
            CLEE_ERROR; /* FIXME CLEE_ERROR from child */
        default:
            /* parent */
            tracee = pid;
            int status;
            if (waitpid(pid, &status, 0) == -1)
            {
                /* waitpid error */
                CLEE_ERROR;
            }
            if (WIFSTOPPED(status)) {
                clee_status(status);
                return;
            }
            else
            {
                // fail on child ptrace/execve error
                CLEE_ERROR;
            }
    }
}

void clee_signal_chld(int signo) {
    pid_t child;
    int status;
    if ((child = waitpid(tracee, &status, WNOHANG|WUNTRACED|WCONTINUED)) == -1) {
        /* waitpid failure */
        CLEE_ERROR;
    }
    if (child == 0)
    {
        /* no change */
        return;
    }
    clee_status(status);
}

pid_t clee_wait(int *status, int options) {
    pid_t pid;
    if ((pid = waitpid(tracee, status, options)) == -1) {
        CLEE_ERROR;
    }
    clee_status(*status);
    return pid;
}

void clee_status(int status) {
}
