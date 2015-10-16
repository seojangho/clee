#ifndef CLEE_H
#define CLEE_H

#include <unistd.h>

/* create child process using fork and execve, and ptrace it
 * Error: return 0 and errno */
int clee_start(const char *filename, char *const argv[], char *const envp[]);

#endif
