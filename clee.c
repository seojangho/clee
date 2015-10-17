#include "clee.h"

static _Bool tracing;

void clee_init() {
    errno = 0;
    signal(SIGCHLD, clee_signal_chld);
    if (errno) {
        CLEE_ERROR;
    }
    tracing = false;
}

pid_t clee_start(const char *filename, char *const argv[], char *const envp[]) {
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
        default: ;
            /* parent */
            int status;
            if (waitpid(pid, &status, 0) == -1)
            {
                /* waitpid error */
                CLEE_ERROR;
            }
            if (WIFSTOPPED(status)) {
                long const options =
                    PTRACE_O_TRACEFORK |
                    PTRACE_O_TRACEVFORK |
                    PTRACE_O_TRACECLONE;
                if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) == -1) {
                    /* ptrace error */
                    CLEE_ERROR;
                }
                tracing = true;
                clee_status(pid, status);
                return pid;
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
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG|WUNTRACED|WCONTINUED|__WALL)) > 0) {
        clee_status(pid, status);
    }
    if (pid == -1 && errno != ECHILD) {
        /* waitpid failure */
        CLEE_ERROR;
    }
}

pid_t clee_wait(pid_t pid_arg, int *user_status, int options) {
    if (!tracing) {
        CLEE_ERROR;
    }
    pid_t pid;
    int status;
    if ((pid = waitpid(pid_arg, &status, options)) == -1) {
        CLEE_ERROR;
    }
    if (user_status != NULL) {
        *user_status = status;
    }
    if (pid > 0) {
        clee_status(pid, status);
    }
    return pid;
}

void clee_continue(pid_t pid) {
    if (!tracing) {
        CLEE_ERROR;
    }
    ptrace(PTRACE_CONT, pid, NULL, NULL);
}

void clee_status(pid_t pid, int status) {
    if (!tracing) {
        CLEE_ERROR;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
    }
}
