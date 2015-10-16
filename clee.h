#ifndef CLEE_H
#define CLEE_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

/* create child process using fork and execve, and ptrace it
 * Error: return 0 and errno */
int clee_start(const char *filename, char *const argv[], char *const envp[]);

#endif
