#include "clee.h"
#include "interposition.h"

void clee_onSyscallEntry() {
    printf("%d entry: %d(%s)\n", clee_syscall_pid(), clee_syscall_num(), clee_syscall_name());
}
void clee_onSyscallExit() {
}

int main(int argc, char **argv) {
    clee_init();
    clee_start(argv[1], argv+1, NULL);
    return 0;
}
