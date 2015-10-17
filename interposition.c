#include "clee.h"
#include "interposition.h"

int main(int argc, char **argv) {
    clee_init();
    clee_start(argv[1], argv+1, NULL);
    printf("continuing...\n");
    clee_continue();
    printf("continued\n");
    clee_wait(NULL, 0);
    return 0;
}
