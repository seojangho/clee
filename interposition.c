#include "clee.h"
#include "interposition.h"

void onSyscallEntry() {
    if (clee_syscall_num() == 1) {
        printf("%d entry: %d(%s) - %d\n", clee_syscall_pid(), clee_syscall_num(), clee_syscall_name(), clee_get_arg(0));
        clee_set_arg(0, 1);
    }
}
void onSyscallExit() {
    if (clee_syscall_num() == 1) {
        printf("%d entry: %d(%s) - %d = %d\n", clee_syscall_pid(), clee_syscall_num(), clee_syscall_name(), clee_get_arg(0), clee_syscall_result());
    }
}

int main(int argc, char **argv) {
    clee_init();
    assert(clee_get_trigger(syscall_entry) == NULL);
    assert(clee_set_trigger(syscall_entry, onSyscallEntry) == NULL);
    assert(clee_set_trigger(syscall_entry, onSyscallEntry) == onSyscallEntry);
    assert(clee_get_trigger(syscall_entry) == onSyscallEntry);
    clee_set_trigger(syscall_exit, onSyscallExit);
    clee_start(argv[1], argv+1, NULL);
    return 0;
}
