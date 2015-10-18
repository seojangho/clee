#include "clee.h"

void onSyscallEntry() {
    pid_t pid = clee_pid();
    if (clee_syscall_num() == 1) {
        clee_write("\0", (void*)clee_get_arg(1), 1);
    }
    clee_behave(terminate, 0);
}

int main(int argc, char **argv, char **envp) {
    clee_init();
    clee_set_trigger(syscall_entry, onSyscallEntry);
    clee(argv[1], argv+1, envp, next_syscall, NULL, 0);
    return 0;
}
