#include "esp_headers.hpp" // ESP-common headers

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <mc_scverify.h>   // Enable SCVerify

#include "tests/ecb_tests.h"
#include "tests/cbc_tests.h"
#include "tests/gcm_tests.h"

CCS_MAIN(int argc, char **argv)
{
    int errors = 0;

    (void) argc; /* silent warning */
    (void) argv; /* silent warning */

    printf("-----------------------------------------------------------\n");

    printf("START - MCT - operation mode: ECB\n");
    errors += ecb_mct128();
//    errors += ecb_mct192();
//    errors += ecb_mct256();
    printf("END - MCT - operation mode: ECB\n");

    printf("-----------------------------------------------------------\n");

//    printf("START - KAT - operation mode: ECB\n");
//    errors += ecb_gfsbox128();
//    errors += ecb_gfsbox192();
//    errors += ecb_gfsbox256();
//    errors += ecb_keysbox128();
//    errors += ecb_keysbox192();
//    errors += ecb_keysbox256();
//    errors += ecb_vartxt128();
//    errors += ecb_vartxt192();
//    errors += ecb_vartxt256();
//    errors += ecb_varkey128();
//    errors += ecb_varkey192();
//    errors += ecb_varkey256();
//    printf("END - KAT - operation mode: ECB\n");
//
//    printf("-----------------------------------------------------------\n");
//
//    printf("START - MMT - operation mode: ECB\n");
//    errors += ecb_mmt128();
//    errors += ecb_mmt192();
//    errors += ecb_mmt256();
//    printf("END - MMT - operation mode: ECB\n");
//
//    printf("-----------------------------------------------------------\n");
//
//    printf("START - MCT - operation mode: CBC\n");
//    errors += cbc_mct128();
//    errors += cbc_mct192();
//    errors += cbc_mct256();
//    printf("END - MCT - operation mode: CBC\n");
//
//    printf("-----------------------------------------------------------\n");
//
//    printf("START - KAT - operation mode: CBC\n");
//    errors += cbc_gfsbox128();
//    errors += cbc_gfsbox192();
//    errors += cbc_gfsbox256();
//    errors += cbc_keysbox128();
//    errors += cbc_keysbox192();
//    errors += cbc_keysbox256();
//    errors += cbc_vartxt128();
//    errors += cbc_vartxt192();
//    errors += cbc_vartxt256();
//    errors += cbc_varkey128();
//    errors += cbc_varkey192();
//    errors += cbc_varkey256();
//    printf("END - KAT - operation mode: CBC\n");
//
//    printf("-----------------------------------------------------------\n");
//
//    printf("START - MMT - operation mode: CBC\n");
//    errors += cbc_mmt128();
//    errors += cbc_mmt192();
//    errors += cbc_mmt256();
//    printf("END - MMT - operation mode: CBC\n");
//
//    printf("-----------------------------------------------------------\n");
//
//    printf("START - INT - operation mode: GCM\n");
//    errors += gcm_int128();
//    errors += gcm_int192();
//    errors += gcm_int256();
//    printf("END - INT - operation mode: GCM\n");
//
//    printf("-----------------------------------------------------------\n");
//
//    printf("START - EXT - operation mode: GCM\n");
//    errors += gcm_ext128();
//    errors += gcm_ext192();
//    errors += gcm_ext256();
//    printf("END - EXT - operation mode: GCM\n");
//
//    printf("-----------------------------------------------------------\n");
//
//    printf("START - DEC - operation mode: GCM\n");
//    errors += gcm_dec128();
//    errors += gcm_dec192();
//    errors += gcm_dec256();
//    printf("END - DEC - operation mode: GCM\n");
//
//    printf("-----------------------------------------------------------\n");

    printf("TOTAL ERRORS %d\n", errors);

    CCS_RETURN(0);
}
