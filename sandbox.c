#include "sandbox.h"
#include "clee.h"

#define DENIED_SYSCALLS 209

static _Bool option_enforcing = false;
static _Bool option_showall = false;
static const int forbidden[DENIED_SYSCALLS + 1] = {1, 2, 8, 9, 10, 11, 13, 14, 15, 16, 18, 20, 22, 25, 26, 28, 30, 31, 32, 33, 37, 38, 40, 41, 42, 43, 44, 46, 49, 50, 53, 54, 56, 57, 58, 61, 62, 64, 65, 66, 67, 69, 71, 72, 73, 74, 75, 76, 77, 80, 81, 82, 83, 84, 85, 86, 87, 88, 90, 91, 92, 93, 94, 95, 103, 105, 106, 109, 112, 113, 114, 116, 117, 119, 122, 123, 126, 130, 131, 132, 133, 134, 135, 141, 142, 144, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 179, 180, 182, 183, 184, 185, 188, 189, 190, 197, 198, 199, 200, 202, 203, 205, 206, 207, 209, 210, 213, 214, 215, 216, 218, 219, 220, 221, 222, 223, 226, 227, 233, 234, 235, 236, 237, 238, 240, 241, 242, 244, 245, 246, 248, 249, 250, 251, 253, 254, 255, 256, 258, 259, 260, 261, 262, 263, 264, 265, 266, 268, 269, 272, 273, 275, 276, 277, 278, 279, 280, 282, 283, 284, 285, 286, 288, 289, 290, 291, 292, 293, 294, 296, 297, 300, 301, 302, 305, 306, 307, 308, 311, 312, 313, -1};

void onSyscallExit() {
    printf("%s(%d) = %d\n", clee_syscall_name(), clee_syscall_num(), clee_syscall_result());
}
void onExit() {
    printf("** process %d exited with code %d **\n", clee_pid(), clee_exit_code());
}
void onSeccomp() {
    printf("[Detected] %s(%d)\n", clee_syscall_name(), clee_syscall_num());
    if (option_enforcing) {
        printf("No mercy!...\n");
        clee_behave(terminate, 0);
    } else {
        getchar();
    }
}

int main(int argc, char **argv, char **envp) {
    int param_opt;
    while ((param_opt = getopt(argc, argv, "adesh")) != -1) {
        switch (param_opt) {
            case 'a':
                option_showall = true;
                break;
            case 'd':
                option_enforcing = false;
                break;
            case 'e':
                option_enforcing = true;
                break;
            case 's':
                showpolicy();
                exit(0);
                break;
            case 'h':
                showhelp(argv[0]);
                exit(0);
            case '?':
                showhelp(argv[0]);
                exit(1);
        }
    }
    struct sock_filter filter[DENIED_SYSCALLS + 3];
    filter[0].code = (unsigned short)(BPF_LD | BPF_W | BPF_ABS);
    filter[0].jt = filter[0].jf = 0;
    filter[0].k = offsetof(struct seccomp_data, nr);

    int i;
    for (i = 1;; i++) {
        if (forbidden[i-1] == -1) {
            break;
        }
        filter[i].code = (unsigned short)(BPF_JMP | BPF_JEQ | BPF_K);
        filter[i].jt = DENIED_SYSCALLS - i + 1;
        filter[i].jf = 0;
        filter[i].k = forbidden[i-1];
    }

    filter[i].code = (unsigned short)(BPF_RET | BPF_K);
    filter[i].jt = filter[i].jf = 0;
    filter[i].k = SECCOMP_RET_ALLOW;

    i++;
    filter[i].code = (unsigned short)(BPF_RET | BPF_K);
    filter[i].jt = filter[i].jf = 0;
    filter[i].k = SECCOMP_RET_TRACE;

    if (optind == argc) {
        showhelp(argv[0]);
        exit(1);
    }

    clee_init();
    clee_set_trigger(exited, onExit);
    clee_set_trigger(syscall_exit, onSyscallExit);
    clee_set_trigger(syscall_seccomp, onSeccomp);
    clee(argv[optind], argv + optind, envp, option_showall ? next_syscall : next, filter, sizeof(filter)/sizeof(filter[0]));

    return 0;
}

void showhelp(char *pgname) {
    printf("Usage: %s: [options] -- PROG [ARGS]\n\n", pgname);
    printf("sandboxing \n\
\n\
Options: \n\
  -h    show this help message and exit \n\
  -a    show all system calls \n\
  -d    permissive policy [default] \n\
  -e    enforcing policy \n\
  -s    show policy \n\
\nUsing -a means not utilizing benefits of seccomp\n");
}

void showpolicy() {
    printf("List of forbidden system calls:\n");
    int i;
    for (i = 0;; i++)
    {
        if (forbidden[i] == -1) {
            break;
        }
        printf("%s(%d)\n", clee_syscall_num2name(forbidden[i]), forbidden[i]);
    }
}
