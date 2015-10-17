#ifndef SYSENT_H
#define SYSENT_H

struct sysent {
    const char *sys_name;
};

const char* clee_syscall_name(int i);

#endif
