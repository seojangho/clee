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

#ifndef CLEE_H
#define CLEE_H

#define _GNU_SOURCE
#include <stdlib.h>
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
#include "simclist.h"

#define CLEE_ERROR    {assert(0);}

typedef uint64_t reg;

typedef enum {
    syscall_entry,
    syscall_exit,
    exited,
    terminated,
    continued,
    stopped,
    new_process,
    syscall_clone,
    syscall_fork,
    syscall_vfork,
    syscall_seccomp,
    successful_exec,
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
    void (*new_process)();
    void (*syscall_clone)();
    void (*syscall_fork)();
    void (*syscall_vfork)();
    void (*syscall_seccomp)();
    void (*successful_exec)();
} clee_event_handlers;

typedef struct {
    pid_t pid;
} clee_tracee;

/* create child process using fork and execve, and ptrace it
 * users must close unwanted file handers/etc */
pid_t clee(const char *filename, char *const argv[], char *const envp[], clee_behavior initial_behavior, struct sock_filter *filter, unsigned short len);


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
const char* clee_syscall_num2name(int num);
reg clee_get_arg(int n);
void clee_set_arg(int n, reg value);
reg clee_syscall_result();
int clee_signal();
void clee_kill();

void clee_behave(clee_behavior behavior, int sig);

/* triggers */
void (*clee_set_trigger(clee_events ev, void (*handler)()))();
void (*clee_get_trigger(clee_events ev))();

/* memory */
ssize_t clee_read(void *src, void *dst, size_t len);
ssize_t clee_write(void *src, void *dst, size_t len);

void clee_children_add(pid_t pid);
void clee_children_delete(pid_t pid);
clee_tracee *clee_children_lookup(pid_t pid);

_Bool clee_process_exists(pid_t pid);

enum __ptrace_request clee_behavior2request(clee_behavior behavior);

void clee_syscall_regs_set();
void clee_syscall_regs_get();

struct user_regs_struct *clee_regs();

#endif
