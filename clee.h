#ifndef CLEE_H
#define CLEE_H

#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <signal.h>
#include <stdint.h>

#include "syscalls.h"

#define CLEE_ERROR    {assert(0);}

typedef uint64_t reg;

typedef enum {
    syscall_entry,
    syscall_exit,
} clee_events;

typedef struct {
    void (*syscall_entry)();
    void (*syscall_exit)();
} clee_event_handlers;

/* create child process using fork and execve, and ptrace it
 * users must close unwanted file handers/etc */
pid_t clee_start(const char *filename, char *const argv[], char *const envp[]);


void clee_init();
void clee_main();
void clee_signal_handler();
void clee_syscall(pid_t pid);

reg clee_syscall_num();
pid_t clee_syscall_pid();
const char* clee_syscall_name();
reg clee_get_arg(int n);
void clee_set_arg(int n, reg value);
reg clee_syscall_result();

/* triggers */
void (*clee_set_trigger(clee_events ev, void (*handler)()))();
void (*clee_get_trigger(clee_events ev))();

#endif
