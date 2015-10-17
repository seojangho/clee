#include "clee.h"
#include "interposition.h"

int main(int argc, char **argv) {
    clee_init();
    pid_t main_process = clee_start(argv[1], argv+1, NULL);
    printf("continuing...\n");
    clee_continue(main_process);
    printf("continued\n");
    clee_wait(main_process, NULL, 0);
    return 0;
}
