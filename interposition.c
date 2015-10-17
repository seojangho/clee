#include "interposition.h"
#include "clee.h"

void onSyscallEntry() {
    char buf[1000];
    char empty[30] = {'_'};
    if (clee_syscall_num() == 1) {
        printf("%d entry: %d(%s) - %d\n", clee_pid(), clee_syscall_num(), clee_syscall_name(), clee_get_arg(0));
        clee_read((void*)clee_get_arg(1), buf, 100);
        // printf("BUFFER => %s\n", buf);
        clee_write(empty, (void*)clee_get_arg(1), 1);
        clee_set_arg(0, 1);
    }
}
void onSyscallExit() {
    if (clee_syscall_num() == 1) {
        printf("%d entry: %d(%s) - %d = %d\n", clee_pid(), clee_syscall_num(), clee_syscall_name(), clee_get_arg(0), clee_syscall_result());
    }
}
void onExit() {
    printf("process %d exited with code %d\n", clee_pid(), clee_exit_code());
}

int main(int argc, char **argv) {
    clee_init();
    assert(clee_get_trigger(syscall_entry) == NULL);
    assert(clee_set_trigger(syscall_entry, onSyscallEntry) == NULL);
    assert(clee_set_trigger(syscall_entry, onSyscallEntry) == onSyscallEntry);
    assert(clee_get_trigger(syscall_entry) == onSyscallEntry);
    clee_set_trigger(exited, onExit);
    clee_set_trigger(syscall_exit, onSyscallExit);
    clee(argv[1], argv+1, NULL);
    return 0;
}
