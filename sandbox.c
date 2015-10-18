#include "interpose.h"
#include "clee.h"

static _Bool option_print_syscall = true;
static _Bool option_enforcing = false;

void onSyscallExit() {
    if (option_print_syscall) {
        printf("%s(%d) = %d\n", clee_syscall_name(), clee_syscall_num(), clee_syscall_result());
    }
}
void onExit() {
    printf("** process %d exited with code %d **\n", clee_pid(), clee_exit_code());
}
void onSeccomp() {
    printf("[Detected] %s(%d)\n", clee_syscall_name(), clee_syscall_num());
    getchar();
}

int main(int argc, char **argv, char **envp) {
    int param_opt;
    _Bool seccomp_enabled = false;
    while ((param_opt = getopt(argc, argv, "deqh")) != -1) {
        switch (param_opt) {
            case 'd':
                option_enforcing = false;
                break;
            case 'e':
                option_enforcing = true;
                break;
            case 'q':
                option_print_syscall = false;
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
        BPF_STMT(BPF_RET | BPF_K, option_enforcing ? SECCOMP_RET_KILL : SECCOMP_RET_TRACE),
    };

    if (optind == argc) {
        showhelp(argv[0]);
        exit(1);
    }

    clee_init();
    clee_set_trigger(exited, onExit);
    clee_set_trigger(syscall_exit, onSyscallExit);
    clee_set_trigger(syscall_seccomp, onSeccomp);
    clee(argv[optind], argv + optind, envp, next_syscall, filter, sizeof(filter)/sizeof(filter[0]));

    return 0;
}

void showhelp(char *pgname) {
    printf("Usage: %s: [options] -- PROG [ARGS]\n\n", pgname);
    printf("sandboxing \n\
\n\
Options: \n\
  -h    show this help message and exit \n\
  -d    permissive policy [default] \n\
  -e    enforcing policy \n\
  -q    do not print system calls \n");
}
