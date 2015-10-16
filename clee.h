#ifndef CLEE_H
#define CLEE_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

/* tracee status tracking */
typedef enum {
    started,
    stopped,
    terminated,
}
clee_tracee_status;

void clee_status(clee_tracee_status tracee_status, int status);

/* create child process using fork and execve, and ptrace it
 * Error: return 0 and errno
 * users must close unwanted file handers/etc */
int clee_start(const char *filename, char *const argv[], char *const envp[]);

#endif
