#ifndef CLEE_H
#define CLEE_H

#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>

#define CLEE_ERROR    {assert(0);}

/* child process status tracker */
void clee_status(pid_t pid, int status);
void clee_signal_chld(int signo);

/* create child process using fork and execve, and ptrace it
 * users must close unwanted file handers/etc */
pid_t clee_start(const char *filename, char *const argv[], char *const envp[]);


void clee_init();
pid_t clee_wait(pid_t pid, int *status, int options);
void clee_continue(pid_t pid);

#endif
