#ifndef CLEE_H
#define CLEE_H

#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>

void clee_status(int status);

void clee_signal_chld(int signo);

/* create child process using fork and execve, and ptrace it
 * Error: return 0 and errno
 * users must close unwanted file handers/etc */
int clee_start(const char *filename, char *const argv[], char *const envp[]);

int clee_init();

#endif
