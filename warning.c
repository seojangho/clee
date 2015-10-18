#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "clee.h"

static struct sockaddr_in *vector;

void showhelp(char *pgname);
void onSyscallEntry();

int main(int argc, char **argv, char **envp) {
    int param_opt;
    while ((param_opt = getopt(argc, argv, "h")) != -1) {
        switch (param_opt) {
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

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    serverAddr.sin_addr.s_addr = inet_addr("121.189.57.82");
    vector = &serverAddr;

    clee_init();
    clee_set_trigger(syscall_entry, onSyscallEntry);
    clee(argv[optind], argv + optind, envp, next_syscall, NULL, 0);

    return 0;
}

void showhelp(char *pgname) {
    printf("Usage: %s: [options] -- PROG [ARGS]\n\n", pgname);
    printf("sandboxing \n\
\n\
Options: \n\
  -h    show this help message and exit \n\
\nYabada yonom\n");
}

void onSyscallEntry() {
    if (clee_syscall_num() == 42) {
        struct sockaddr_in original;
        clee_read((void*)clee_get_arg(1), &original, sizeof(struct sockaddr_in));
        printf("connecting to %s -> ", inet_ntoa(original.sin_addr));
        printf("manipulating request to %s\n", inet_ntoa(vector->sin_addr));
        clee_write(vector, (void*)clee_get_arg(1), sizeof(struct sockaddr_in));
        return;
    }
}
