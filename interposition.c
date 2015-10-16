#include "clee.h"
#include "interposition.h"

int main(int argc, char **argv) {
    assert(clee_start(argv[1], argv+1, NULL));
    return 0;
}
