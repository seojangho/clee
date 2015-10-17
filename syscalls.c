#include "syscalls.h"

static const struct sysent syscalls[] = {
#include "syscallent.h"
};

const char* clee_syscall_name(int i) {
    return syscalls[i].sys_name;
}
