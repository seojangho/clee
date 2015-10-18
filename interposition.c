#include "interposition.h"
#include "clee.h"

void onSyscallEntry() {
}
void onSyscallExit() {
}
void onExit() {
    printf("process %d exited with code %d\n", clee_pid(), clee_exit_code());
}

int main(int argc, char **argv, char **envp) {
    clee_init();
    assert(clee_get_trigger(syscall_entry) == NULL);
    assert(clee_set_trigger(syscall_entry, onSyscallEntry) == NULL);
    assert(clee_set_trigger(syscall_entry, onSyscallEntry) == onSyscallEntry);
    assert(clee_get_trigger(syscall_entry) == onSyscallEntry);
    clee_set_trigger(exited, onExit);
    clee_set_trigger(syscall_exit, onSyscallExit);
    clee(argv[1], argv+1, envp);
    return 0;
}
