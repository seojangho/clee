#include "clee.h"
#include "interposition.h"

int main(int argc, char **argv) {
    clee_init();
    pid_t main_process = clee_start(argv[1], argv+1, NULL);
    return 0;
}
