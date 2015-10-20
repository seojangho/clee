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
