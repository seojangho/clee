#include "interposition.h"
#include "clee.h"

static _Bool option_print_syscall = true;
static _Bool option_write_stdout = false;
static _Bool option_nullify_stdout = false;
static _Bool option_write2read = false;

void onSyscallEntry() {
    if (clee_syscall_num() == 1 && option_write2read) {
        clee_syscall_set(0);
    }
    if (clee_syscall_num() == 1 && option_write_stdout) {
        clee_set_arg(0, 1);
    }
    if (clee_syscall_num() == 1 && clee_get_arg(0) == 1 && option_nullify_stdout) {
        char null = '\0';
        int len = clee_get_arg(2);
        void *pos = (void*)clee_get_arg(1);
        int i;
        for (i = 0; i < len; i++) {
            clee_write(&null, pos + i, 1);
        }
    }
}
void onStop() {
    printf("one more step over syscall\n");
}
void onNew() {
    printf("new process %d!\n", clee_pid());
}
void onSyscallExit() {
    if (option_print_syscall) {
        printf("%s(%d) = %d\n", clee_syscall_name(), clee_syscall_num(), clee_syscall_result());
    }
    clee_behave(next_step, 0);
}
void onExit() {
    printf("** process %d exited with code %d **\n", clee_pid(), clee_exit_code());
}

int main(int argc, char **argv, char **envp) {
    int param_opt;
    _Bool seccomp_enabled = false;
    while ((param_opt = getopt(argc, argv, "abcoqh")) != -1) {
        switch (param_opt) {
            case 'a':
                option_write_stdout = true;
                break;
            case 'b':
                option_nullify_stdout = true;
                break;
            case 'c':
                option_write2read = true;
                break;
            case 'q':
                option_print_syscall = false;
                break;
            case 'o':
                seccomp_enabled = true;
                break;
            case 'h':
                showhelp(argv[0]);
                exit(0);
            case '?':
                showhelp(argv[0]);
                exit(1);
        }
    }
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };

    if (optind == argc) {
        showhelp(argv[0]);
        exit(1);
    }

    clee_init();
    clee_set_trigger(stopped, onStop);
    clee_set_trigger(exited, onExit);
    clee_set_trigger(syscall_entry, onSyscallEntry);
    clee_set_trigger(syscall_exit, onSyscallExit);
    clee_set_trigger(new_process, onNew);
    clee(argv[optind], argv + optind, envp, next_syscall, seccomp_enabled ? filter : NULL, 4);

    return 0;
}

void showhelp(char *pgname) {
    printf("Usage: %s: [options] -- PROG [ARGS]\n\n", pgname);
    printf("syscall interposition \n\
\n\
Options: \n\
  -h    show this help message and exit \n\
  -a    forward all write calls to STDOUT \n\
  -b    nullify all write buffers \n\
  -c    convert write calls to read calls \n\
  -o    use seccomp to block open(2) \n\
  -q    do not print system calls\n");
}
