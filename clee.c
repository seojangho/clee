#include "clee.h"

static _Bool tracing;
static struct user_regs_struct syscall_regs;
static pid_t syscall_pid;
static clee_event_handlers event_handlers;

void clee_init() {
    tracing = false;
    event_handlers.syscall_entry = NULL;
    event_handlers.syscall_exit = NULL;
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
    tracing = false;
}

void clee_syscall(pid_t pid) {
    if (ptrace(PTRACE_GETREGS, pid, 0, &syscall_regs) == -1) {
        CLEE_ERROR;
    }
    syscall_pid = pid;
    if (syscall_regs.rax == -ENOSYS) {
        if (event_handlers.syscall_entry != NULL) {
            (event_handlers.syscall_entry)();
        }
        if (ptrace(PTRACE_SETREGS, pid, 0, &syscall_regs) == -1) {
            CLEE_ERROR;
        }
    } else {
        if (event_handlers.syscall_exit != NULL) {
            (event_handlers.syscall_exit)();
        }
    }
}

pid_t clee_syscall_pid() {
    return syscall_pid;
}

reg clee_syscall_num() {
    return syscall_regs.orig_rax;
}

const char* clee_syscall_name() {
    return clee_syscall_namelookup(syscall_regs.orig_rax);
}

reg clee_get_arg(int n) {
    switch (n) {
        case 0:
            return syscall_regs.rdi;
        case 1:
            return syscall_regs.rsi;
        case 2:
            return syscall_regs.rdx;
        case 3:
            return syscall_regs.r10;
        case 4:
            return syscall_regs.r8;
        case 5:
            return syscall_regs.r9;
        default:
            CLEE_ERROR;
    }
}

void clee_set_arg(int n, reg value) {
    switch (n) {
        case 0:
            syscall_regs.rdi = value;
            return;
        case 1:
            syscall_regs.rsi = value;
            return;
        case 2:
            syscall_regs.rdx = value;
            return;
        case 3:
            syscall_regs.r10 = value;
            return;
        case 4:
            syscall_regs.r8 = value;
            return;
        case 5:
            syscall_regs.r9 = value;
            return;
        default:
            CLEE_ERROR;
    }
}

reg clee_syscall_result() {
    return syscall_regs.rax;
}

void (*clee_set_trigger(clee_events ev, void (*handler)()))() {
    void (*old_handler)();
    switch (ev) {
        case syscall_entry:
            old_handler = event_handlers.syscall_entry;
            event_handlers.syscall_entry = handler;
            return old_handler;
        case syscall_exit:
            old_handler = event_handlers.syscall_exit;
            event_handlers.syscall_exit = handler;
            return old_handler;
        default:
            CLEE_ERROR;
    }
}

void (*clee_get_trigger(clee_events ev))() {
    switch (ev) {
        case syscall_entry:
            return event_handlers.syscall_entry;
        case syscall_exit:
            return event_handlers.syscall_exit;
        default:
            CLEE_ERROR;
    }
}

void clee_signal_handler(int sig) {
}
