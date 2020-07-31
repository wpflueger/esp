#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "rsa.h"
#include "tests/tests.h"

int main(int argc, char* argv[])
{
    int errors = 0;

    (void) argc; /* silent warning */
    (void) argv; /* silent warning */

    printf("-----------------------------------------------------------\n");

    printf("START - RSASASP - simple tests\n");
    errors += rsa_sasp();
    printf("END - RSASASP - simple tests\n");

    printf("-----------------------------------------------------------\n");

    printf("TOTAL ERRORS %d\n", errors);

    return 0;
}
