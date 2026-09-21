/* ===========================================================================**
**                                                                            **
**  Modulo:            SecLib_Ecc_SelfTest                                    **
**                                                                            **
**  Description:       Known-answer self tests for the SecurityLib ECC        **
**                     extension (P-224 ECDH + ANSI X9.63 KDF/SHA-256).       **
**                                                                            **
**                     Run once on target after SecLib_Init() and             **
**                     SecLib_EccInit() (the RNG-based tests require the      **
**                     generated Csm random service to be initialized).       **
**                     The fixed vectors were generated independently of      **
**                     the mbedtls code under test.                           **
******************************************************************************/
#ifndef SECLIB_ECC_SELFTEST_H
#define SECLIB_ECC_SELFTEST_H

#include "crypto_library_type.h"

/* Test identifiers reported through pFailedTest on failure. */
#define SECLIB_ECC_ST_SHA256_KAT          (1u)
#define SECLIB_ECC_ST_KDF_16B             (2u)
#define SECLIB_ECC_ST_KDF_28B             (3u)
#define SECLIB_ECC_ST_KDF_64B             (4u)
#define SECLIB_ECC_ST_KDF_PARAM           (5u)
#define SECLIB_ECC_ST_MULBASE_D2          (6u)
#define SECLIB_ECC_ST_MULBASE_DA          (7u)
#define SECLIB_ECC_ST_MULPOINT            (8u)
#define SECLIB_ECC_ST_ECDH_A              (9u)
#define SECLIB_ECC_ST_ECDH_B              (10u)
#define SECLIB_ECC_ST_INVALID_CURVE       (11u)
#define SECLIB_ECC_ST_KEYGEN_CONSISTENCY  (12u)

/* Executes all tests. Returns TRUE when every test passed. On failure,
 * *pFailedTest holds the first failed test identifier (may be NULL). */
boolean SecLib_EccSelfTest(uint32 *pFailedTest);

#endif /* SECLIB_ECC_SELFTEST_H */
