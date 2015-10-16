#ifndef CLEE_H
#define CLEE_H

#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>

#define CLEE_ERROR    {assert(0);}

void clee_status(int status);

void clee_signal_chld(int signo);

/* create child process using fork and execve, and ptrace it
 * users must close unwanted file handers/etc */
void clee_start(const char *filename, char *const argv[], char *const envp[]);

void clee_init();

pid_t clee_wait(int *status, int options);

#endif
