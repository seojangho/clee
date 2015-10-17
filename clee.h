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

/* create child process using fork and execve, and ptrace it
 * users must close unwanted file handers/etc */
pid_t clee_start(const char *filename, char *const argv[], char *const envp[]);


void clee_init();

#endif
