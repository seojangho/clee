#include "clee.h"

static _Bool tracing;
static pid_t tracee;

void clee_init() {
    errno = 0;
    signal(SIGCHLD, clee_signal_chld);
    if (errno) {
        CLEE_ERROR;
    }
    tracing = false;
}

void clee_start(const char *filename, char *const argv[], char *const envp[]) {
    if (tracing) {
        CLEE_ERROR;
    }
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            /* error */
            CLEE_ERROR;
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
                CLEE_ERROR;
            }
            if (WIFSTOPPED(status)) {
                tracing = true;
                clee_status(status);
                return;
            }
            else
            {
                /* fail on child ptrace/execve error */
                CLEE_ERROR;
            }
    }
}

void clee_signal_chld(int signo) {
    if (!tracing) {
        return;
    }
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

pid_t clee_wait(int *user_status, int options) {
    if (!tracing) {
        CLEE_ERROR;
    }
    pid_t pid;
    int status;
    if ((pid = waitpid(tracee, &status, options)) == -1) {
        CLEE_ERROR;
    }
    if (user_status != NULL) {
        *user_status = status;
    }
    clee_status(status);
    return pid;
}

void clee_continue() {
    if (!tracing) {
        CLEE_ERROR;
    }
    ptrace(PTRACE_CONT, tracee, NULL, NULL);
}

void clee_status(int status) {
    if (!tracing) {
        CLEE_ERROR;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        tracing = false;
    }
}
