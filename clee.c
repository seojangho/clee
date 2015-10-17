#include "clee.h"

static _Bool tracing;

void clee_init() {
    tracing = false;
    if (signal(SIGINT, clee_signal_handler) == SIG_ERR) {
        CLEE_ERROR;
    }
    if (signal(SIGTSTP, clee_signal_handler) == SIG_ERR) {
        CLEE_ERROR;
    }
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
                    PTRACE_O_TRACESYSGOOD |
                    PTRACE_O_TRACEFORK |
                    PTRACE_O_TRACEVFORK |
                    PTRACE_O_TRACECLONE;
                if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) == -1) {
                    /* ptrace error */
                    CLEE_ERROR;
                }
                tracing = true;
                ptrace(PTRACE_SYSCALL, pid, NULL, 0);
                clee_main();
                return pid;
            }
            else
            {
                /* fail on child ptrace/execve error */
                CLEE_ERROR;
            }
    }
}

void clee_main() {
    if (!tracing) {
        CLEE_ERROR;
    }
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, __WALL)) > 0) {
        if (WIFSTOPPED(status)) {
            int const cause = WSTOPSIG(status);
            int sig2send = 0;
            if (cause == (SIGTRAP|0x80)) {
                clee_syscall(pid);
            }
            if (cause != SIGTRAP && cause != (SIGTRAP|0x80)) {
                sig2send = cause;
            }
            if (ptrace(PTRACE_SYSCALL, pid, NULL, sig2send) == -1) {
                CLEE_ERROR;
            }
        } else if (WIFEXITED(status)) {
            int const exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            int const cause = WTERMSIG(status);
        } else if (WIFCONTINUED(status)) {
        } else {
            CLEE_ERROR;
        }
    }
    if (pid == -1 && errno != ECHILD) {
        CLEE_ERROR;
    }
}

void clee_syscall(pid_t pid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        CLEE_ERROR;
    }
    if (regs.rax == -ENOSYS) {
        printf("%d\n", regs.orig_rax);
    }
}

void clee_signal_handler(int sig) {
}
