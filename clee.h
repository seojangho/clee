#ifndef CLEE_H
#define CLEE_H

#define _GNU_SOURCE
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <stddef.h>
#include <asm/unistd.h>

#include "syscalls.h"

#define CLEE_ERROR    {assert(0);}

typedef uint64_t reg;

typedef enum {
    syscall_entry,
    syscall_exit,
    exited,
    terminated,
    continued,
    stopped,
} clee_events;

typedef enum {
    terminate,
    interrupt,
    detach,
    next,
    next_syscall,
    next_step,
} clee_behavior;

typedef struct {
    void (*syscall_entry)();
    void (*syscall_exit)();
    void (*exited)();
    void (*terminated)();
    void (*continued)();
    void (*stopped)();
} clee_event_handlers;

/* create child process using fork and execve, and ptrace it
 * users must close unwanted file handers/etc */
pid_t clee(const char *filename, char *const argv[], char *const envp[], struct sock_filter *filter, unsigned short len);


void clee_init();
void clee_main();
void clee_signal_handler();
void clee_syscall();

reg clee_syscall_num();
void clee_syscall_set(reg value);
pid_t clee_pid();
int clee_exit_code();
int clee_terminate_cause();
const char* clee_syscall_name();
reg clee_get_arg(int n);
void clee_set_arg(int n, reg value);
reg clee_syscall_result();
int clee_signal();

void clee_behave(clee_behavior behavior, int sig);

/* triggers */
void (*clee_set_trigger(clee_events ev, void (*handler)()))();
void (*clee_get_trigger(clee_events ev))();

/* memory */
ssize_t clee_read(void *src, void *dst, size_t len);
ssize_t clee_write(void *src, void *dst, size_t len);

#endif
