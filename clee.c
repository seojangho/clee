#include "clee.h"

static pid_t tracee;

int clee_init() {
    errno = 0;
    signal(SIGCHLD, clee_signal_chld);
    if (errno) {
        return 0;
    }
    return 1;
}

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
            if (WIFSTOPPED(status)) {
                clee_status(status);
                return 1;
            }
            else
            {
                // fail on child ptrace/execve error
                return 0;
            }
    }
}

void clee_signal_chld(int signo) {
    pid_t child;
    int status;
    if ((child = waitpid(tracee, &status, WNOHANG|WUNTRACED|WCONTINUED)) == -1) {
        /* waitpid failure */
        assert(0);
    }
    if (child == 0)
    {
        /* no change */
        return;
    }
    clee_status(status);
}

void clee_status(int status) {
}
