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
    if (clee_syscall_num() == 1 && clee_get_arg(0) == 1) {
        char null = '\0';
        int len = clee_get_arg(2);
        void *pos = (void*)clee_get_arg(1);
        int i;
        for (i = 0; i < len; i++) {
            clee_write(&null, pos + i, 1);
        }
    }
}
void onSyscallExit() {
    if (option_print_syscall) {
        printf("%s(%d) = %d\n", clee_syscall_name(), clee_syscall_num(), clee_syscall_result());
    }
}
void onExit() {
    printf("** process %d exited with code %d **\n", clee_pid(), clee_exit_code());
}

int main(int argc, char **argv, char **envp) {
    int param_opt;
    while ((param_opt = getopt(argc, argv, "abcqh")) != -1) {
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
            case 'h':
                showhelp(argv[0]);
                exit(0);
            case '?':
                showhelp(argv[0]);
                exit(1);
        }
    }

    if (optind == argc) {
        showhelp(argv[0]);
        exit(1);
    }

    clee_init();
    clee_set_trigger(exited, onExit);
    clee_set_trigger(syscall_entry, onSyscallEntry);
    clee_set_trigger(syscall_exit, onSyscallExit);
    clee(argv[optind], argv + optind, envp);

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
  -q    do not print system calls\n");
}
