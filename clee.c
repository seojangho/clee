/*
 * Copyright (c) 2015 JangHo Seo <contact@jangho.kr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "clee.h"

static _Bool tracing;
static struct user_regs_struct syscall_regs;
static pid_t event_pid;
static clee_event_handlers event_handlers;
static int exit_code;
static int terminate_cause;
static clee_behavior stopped_behavior;
static clee_behavior default_behavior;
static int stopped_signal;
static int stopped_cause;
static list_t children;

void clee_init() {
    tracing = false;
    list_init(&children);
    event_handlers.syscall_entry = NULL;
    event_handlers.syscall_exit = NULL;
    event_handlers.exited = NULL;
    event_handlers.terminated = NULL;
    event_handlers.continued = NULL;
    event_handlers.stopped = NULL;
    event_handlers.new_process = NULL;
    event_handlers.syscall_clone = NULL;
    event_handlers.syscall_fork = NULL;
    event_handlers.syscall_vfork = NULL;
    event_handlers.syscall_seccomp = NULL;
    event_handlers.successful_exec = NULL;
    if (signal(SIGTERM, clee_signal_handler) == SIG_ERR) {
        CLEE_ERROR;
    }
}

pid_t clee(const char *filename, char *const argv[], char *const envp[], clee_behavior initial_behavior, struct sock_filter *filter, unsigned short len) {
    if (tracing) {
        CLEE_ERROR;
    }
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            /* error */
            CLEE_ERROR;
        case 0:
            if (filter != NULL) {
                if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
                    _exit(1);
                }
                struct sock_fprog prog = {
                    .len = len,
                    .filter = filter,
                };
                if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
                    _exit(1);
                }
            }
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
            clee_children_add(pid);
            if (WIFSTOPPED(status)) {
                long const options =
                    PTRACE_O_TRACESECCOMP |
                    PTRACE_O_TRACESYSGOOD |
                    PTRACE_O_TRACEFORK |
                    PTRACE_O_TRACEVFORK |
                    PTRACE_O_TRACECLONE;
                if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) == -1) {
                    /* ptrace error */
                    CLEE_ERROR;
                }
                tracing = true;
                default_behavior = initial_behavior;
                ptrace(clee_behavior2request(initial_behavior), pid, NULL, 0);
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
        event_pid = pid;
        if (WIFSTOPPED(status)) {
            enum __ptrace_request request;
            stopped_cause = WSTOPSIG(status);
            stopped_behavior = default_behavior;
            if (stopped_cause == (SIGTRAP|0x80)) {
                stopped_signal = 0;
                clee_syscall(pid);
            } else if (stopped_cause == SIGTRAP) {
                stopped_signal = stopped_cause;
                const int st = status >> 8;
                if (st == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
                    clee_syscall_regs_get();
                    if (event_handlers.syscall_clone != NULL) {
                        (event_handlers.syscall_clone)();
                    }
                    clee_syscall_regs_set();
                } else if (st == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
                    clee_syscall_regs_get();
                    if (event_handlers.syscall_fork != NULL) {
                        (event_handlers.syscall_fork)();
                    }
                    clee_syscall_regs_set();
                } else if (st == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
                    clee_syscall_regs_get();
                    if (event_handlers.syscall_vfork != NULL) {
                        (event_handlers.syscall_vfork)();
                    }
                    clee_syscall_regs_set();
                } else if (st == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
                    clee_syscall_regs_get();
                    if (event_handlers.syscall_seccomp != NULL) {
                        (event_handlers.syscall_seccomp)();
                    }
                    clee_syscall_regs_set();
                } else {
                    /* successful exec */
                    if (event_handlers.successful_exec != NULL) {
                        (event_handlers.successful_exec)();
                    }
                }
            } else if (stopped_cause == SIGSTOP && clee_children_lookup(pid) == NULL) {
                stopped_signal = stopped_cause;
                clee_children_add(pid);
                if (event_handlers.new_process != NULL) {
                    (event_handlers.new_process)();
                }
            } else {
                stopped_signal = stopped_cause;
                if (event_handlers.stopped != NULL) {
                    (event_handlers.stopped)();
                }
            }

            if (stopped_behavior == terminate) {
                kill(pid, SIGKILL);
            } else {
                request = clee_behavior2request(stopped_behavior);

                if (ptrace(request, pid, NULL, stopped_signal) == -1) {
                    CLEE_ERROR;
                }
            }
        } else if (WIFEXITED(status)) {
            clee_children_delete(pid);
            exit_code = WEXITSTATUS(status);
            if (event_handlers.exited != NULL) {
                (event_handlers.exited)();
            }
        } else if (WIFSIGNALED(status)) {
            clee_children_delete(pid);
            terminate_cause = WTERMSIG(status);
            if (event_handlers.terminated != NULL) {
                (event_handlers.terminated)();
            }
        } else if (WIFCONTINUED(status)) {
            if (event_handlers.continued != NULL) {
                (event_handlers.continued)();
            }
        } else {
            CLEE_ERROR;
        }
    }
    if (pid == -1 && errno != ECHILD) {
        CLEE_ERROR;
    }
    tracing = false;
    if (list_size(&children) != 0) {
        CLEE_ERROR;
    }
}

void clee_syscall() {
    clee_syscall_regs_get();
    if (syscall_regs.rax == -ENOSYS) {
        if (event_handlers.syscall_entry != NULL) {
            (event_handlers.syscall_entry)();
        }
        clee_syscall_regs_set();
    } else {
        if (event_handlers.syscall_exit != NULL) {
            (event_handlers.syscall_exit)();
        }
    }
}

pid_t clee_pid() {
    return event_pid;
}

reg clee_syscall_num() {
    return syscall_regs.orig_rax;
}

void clee_syscall_set(reg value) {
    syscall_regs.orig_rax = value;
}

const char* clee_syscall_name() {
    return clee_syscall_namelookup(syscall_regs.orig_rax);
}

int clee_exit_code() {
    return exit_code;
}

int clee_terminate_cause() {
    return terminate_cause;
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
        case exited:
            old_handler = event_handlers.exited;
            event_handlers.exited = handler;
            return old_handler;
        case terminated:
            old_handler = event_handlers.terminated;
            event_handlers.terminated = handler;
            return old_handler;
        case continued:
            old_handler = event_handlers.continued;
            event_handlers.continued = handler;
            return old_handler;
        case stopped:
            old_handler = event_handlers.stopped;
            event_handlers.stopped = handler;
            return old_handler;
        case new_process:
            old_handler = event_handlers.new_process;
            event_handlers.new_process = handler;
            return old_handler;
        case syscall_clone:
            old_handler = event_handlers.syscall_clone;
            event_handlers.syscall_clone = handler;
            return old_handler;
        case syscall_fork:
            old_handler = event_handlers.syscall_fork;
            event_handlers.syscall_fork = handler;
            return old_handler;
        case syscall_vfork:
            old_handler = event_handlers.syscall_vfork;
            event_handlers.syscall_vfork = handler;
            return old_handler;
        case syscall_seccomp:
            old_handler = event_handlers.syscall_seccomp;
            event_handlers.syscall_seccomp = handler;
            return old_handler;
        case successful_exec:
            old_handler = event_handlers.successful_exec;
            event_handlers.successful_exec = handler;
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
        case exited:
            return event_handlers.exited;
        case terminated:
            return event_handlers.terminated;
        case continued:
            return event_handlers.continued;
        case stopped:
            return event_handlers.stopped;
        case new_process:
            return event_handlers.new_process;
        case syscall_clone:
            return event_handlers.syscall_clone;
        case syscall_fork:
            return event_handlers.syscall_fork;
        case syscall_vfork:
            return event_handlers.syscall_vfork;
        case syscall_seccomp:
            return event_handlers.syscall_seccomp;
        case successful_exec:
            return event_handlers.successful_exec;
        default:
            CLEE_ERROR;
    }
}

ssize_t clee_read(void *src, void *dst, size_t len) {
    struct iovec remote = {src, len};
    struct iovec local = {dst, len};
    ssize_t readed;
    if ((readed = process_vm_readv(event_pid, &local, 1, &remote, 1, 0)) == -1) {
        CLEE_ERROR;
    }
    return readed;
}

ssize_t clee_write(void *src, void *dst, size_t len) {
    struct iovec remote = {dst, len};
    struct iovec local = {src, len};
    ssize_t written;
    if ((written = process_vm_writev(event_pid, &local, 1, &remote, 1, 0)) == -1) {
        CLEE_ERROR;
    }
    return written;
}

void clee_behave(clee_behavior behavior, int sig) {
    stopped_behavior = behavior;
    stopped_signal = sig;
}

int clee_signal() {
    return stopped_cause;
}

void clee_signal_handler(int sig) {
    clee_kill();
}

void clee_kill() {
    while (list_size(&children) > 0) {
        clee_tracee *tracee = list_get_at(&children, 0);
        kill(tracee->pid, 9);
        list_delete_at(&children, 0);
    }
}

void clee_children_add(pid_t pid) {
    clee_tracee *new_tracee = malloc(sizeof(clee_tracee));
    if (new_tracee == NULL) {
        CLEE_ERROR;
    }
    new_tracee->pid = pid;
    list_append(&children, new_tracee);
}

clee_tracee *clee_children_lookup(pid_t pid) {
    clee_tracee *tracee;
    _Bool found = false;
    int i;
    int len = list_size(&children);
    for (i = 0; i < len; i++) {
        tracee = list_get_at(&children, i);
        if (tracee->pid == pid) {
            found = true;
            break;
        }
    }
    return (found ? tracee : NULL);
}

void clee_children_delete(pid_t pid) {
    clee_tracee *tracee = clee_children_lookup(pid);
    if (tracee == NULL) {
        CLEE_ERROR;
    }
    free(tracee);
    list_delete(&children, tracee);
}

_Bool clee_process_exists(pid_t pid) {
    int result = kill(pid, 0);
    if (result == 0) {
        return true;
    } else if (errno == ESRCH) {
        return false;
    } else {
        CLEE_ERROR;
    }
}

enum __ptrace_request clee_behavior2request(clee_behavior behavior) {
    switch (behavior) {
        case interrupt:
            return PTRACE_INTERRUPT;
        case detach:
            return PTRACE_DETACH;
        case next:
            return PTRACE_CONT;
        case next_syscall:
            return PTRACE_SYSCALL;
        case next_step:
            return PTRACE_SINGLESTEP;
        defalt:
            CLEE_ERROR;
    }
}

void clee_syscall_regs_get() {
    if (ptrace(PTRACE_GETREGS, event_pid, 0, &syscall_regs) == -1) {
        CLEE_ERROR;
    }
}

void clee_syscall_regs_set() {
    if (ptrace(PTRACE_SETREGS, event_pid, 0, &syscall_regs) == -1) {
        CLEE_ERROR;
    }
}


struct user_regs_struct *clee_regs() {
    return &syscall_regs;
}

const char* clee_syscall_num2name(int num) {
    return clee_syscall_namelookup(num);
}
