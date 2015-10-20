/*
 * Copyright (c) 2015 JangHo Seo <contact@jangho.kr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
    char *ip = "121.189.57.82"; /* warning.or.kr */
    while ((param_opt = getopt(argc, argv, "i:h")) != -1) {
        switch (param_opt) {
            case 'i':
                ip = optarg;
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

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    vector = &serverAddr;

    clee_init();
    clee_set_trigger(syscall_entry, onSyscallEntry);
    clee(argv[optind], argv + optind, envp, next_syscall, NULL, 0);

    return 0;
}

void showhelp(char *pgname) {
    printf("Usage: %s: [options] -- PROG [ARGS]\n\n", pgname);
    printf("high-level censorship \n\
\n\
Options: \n\
  -h    show this help message and exit \n\
  -i    ipv4 addres (default: 121.189.57.82) \n\
\nJabada yonom\n");
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
