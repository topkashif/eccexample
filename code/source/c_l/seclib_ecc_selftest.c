/* ===========================================================================**
**                                                                            **
**  Modulo:            SecLib_Ecc_SelfTest                                    **
**                                                                            **
**  Description:       Known-answer self tests for the SecurityLib ECC        **
**                     extension. See seclib_ecc_selftest.h.                  **
******************************************************************************/
#include "seclib_ecc.h"
#include "seclib_ecc_selftest.h"

#include <string.h>

/******************************************************************************/
/*                     TEST VECTORS (independently generated)                  */
/******************************************************************************/
/* SHA-256 KAT through the KDF: the X9.63 KDF always appends the 4-byte
 * counter, so with Z = "abc" and empty SharedInfo the first output block
 * is SHA256( "abc" || 0x00000001 ). This validates the hash core, the
 * counter encoding and the byte order in one known answer. */
static const uint8 seclib_st_sha256_msg[3u] =
{
    0x61u, 0x62u, 0x63u
};

static const uint8 seclib_st_sha256_expect[32u] =
{
    0x46u, 0xC3u, 0x86u, 0xEBu, 0xCCu, 0xEFu, 0x82u, 0xBAu,
    0x0Bu, 0xB0u, 0xB0u, 0x95u, 0xAAu, 0xA5u, 0x54u, 0x8Bu,
    0x03u, 0xCDu, 0xFFu, 0x69u, 0x51u, 0x87u, 0x1Cu, 0x6Fu,
    0xB5u, 0x05u, 0xAFu, 0x68u, 0xAFu, 0x68u, 0x83u, 0x32u
};

/* ECDH pair (dA, dB) on secp224r1, big endian. */
static const uint8 seclib_st_dA[28u] =
{
    0x8Bu, 0x3Du, 0x5Cu, 0x6Fu, 0x27u, 0x94u, 0xA1u, 0xB2u,
    0xE3u, 0xF4u, 0xC5u, 0xD6u, 0x07u, 0x18u, 0x29u, 0x3Au,
    0x4Bu, 0x5Cu, 0x6Du, 0x7Eu, 0x8Fu, 0x90u, 0xA1u, 0xB2u,
    0xC3u, 0xD4u, 0xE5u, 0xF6u
};

static const uint8 seclib_st_QA[56u] =
{
    /* x */ 0x25u, 0xC0u, 0xE8u, 0x50u, 0x3Cu, 0xDBu, 0x5Bu, 0x59u,
            0x3Au, 0x78u, 0x7Cu, 0x85u, 0xB2u, 0x75u, 0xC7u, 0x62u,
            0x8Du, 0x0Bu, 0x84u, 0xD6u, 0x12u, 0xA3u, 0xF1u, 0x51u,
            0xA5u, 0x8Du, 0xFEu, 0xD5u,
    /* y */ 0x2Au, 0xCEu, 0xF2u, 0xC9u, 0xB6u, 0x79u, 0x7Eu, 0xCCu,
            0x0Cu, 0xCFu, 0x2Bu, 0xE8u, 0x82u, 0x17u, 0xFFu, 0x9Au,
            0xB6u, 0xADu, 0xFDu, 0xBCu, 0x78u, 0xB2u, 0xCFu, 0x72u,
            0x68u, 0x40u, 0x1Cu, 0x10u
};

static const uint8 seclib_st_dB[28u] =
{
    0x1Fu, 0x2Eu, 0x3Du, 0x4Cu, 0x5Bu, 0x6Au, 0x79u, 0x88u,
    0x07u, 0x16u, 0x25u, 0x34u, 0x43u, 0x52u, 0x61u, 0x70u,
    0x89u, 0xA8u, 0xB7u, 0xC6u, 0xD5u, 0xE4u, 0xF3u, 0xE2u,
    0xD1u, 0xC0u, 0xB9u, 0xA8u
};

static const uint8 seclib_st_QB[56u] =
{
    /* x */ 0xAAu, 0x4Au, 0xB9u, 0x38u, 0x62u, 0x28u, 0x66u, 0x41u,
            0xC0u, 0xA3u, 0xECu, 0x7Au, 0x5Au, 0x66u, 0x02u, 0xC7u,
            0x47u, 0x07u, 0xAEu, 0xACu, 0xC5u, 0xA6u, 0xA3u, 0x54u,
            0xE5u, 0x0Fu, 0x60u, 0x01u,
    /* y */ 0x44u, 0x6Du, 0xD9u, 0x05u, 0xB6u, 0x3Fu, 0xACu, 0x9Fu,
            0x67u, 0xCDu, 0xD0u, 0xD8u, 0x95u, 0x73u, 0x1Bu, 0xCDu,
            0x45u, 0x32u, 0x21u, 0x68u, 0x97u, 0xDAu, 0x87u, 0xA4u,
            0xC2u, 0x04u, 0x43u, 0xB1u
};

/* Shared point K = dA*QB = dB*QA */
static const uint8 seclib_st_K[56u] =
{
    /* x */ 0xE4u, 0x28u, 0xFFu, 0x39u, 0x07u, 0xEBu, 0x5Au, 0xE6u,
            0xC8u, 0xDCu, 0xAAu, 0x48u, 0xEFu, 0x2Du, 0x22u, 0x67u,
            0xD9u, 0x4Eu, 0x21u, 0x8Bu, 0x43u, 0xC3u, 0x95u, 0xD2u,
            0x34u, 0x04u, 0xD6u, 0xC4u,
    /* y */ 0x82u, 0xA6u, 0xACu, 0x06u, 0x92u, 0x6Du, 0x73u, 0xCBu,
            0x68u, 0x68u, 0xE0u, 0xE2u, 0x57u, 0x1Fu, 0xAFu, 0x98u,
            0x4Du, 0x5Fu, 0x97u, 0x4Du, 0xCAu, 0xDDu, 0xDDu, 0x54u,
            0xFDu, 0xFFu, 0x59u, 0xE9u
};

/* 2*G */
static const uint8 seclib_st_2G[56u] =
{
    /* x */ 0x70u, 0x6Au, 0x46u, 0xDCu, 0x76u, 0xDCu, 0xB7u, 0x67u,
            0x98u, 0xE6u, 0x0Eu, 0x6Du, 0x89u, 0x47u, 0x47u, 0x88u,
            0xD1u, 0x6Du, 0xC1u, 0x80u, 0x32u, 0xD2u, 0x68u, 0xFDu,
            0x1Au, 0x70u, 0x4Fu, 0xA6u,
    /* y */ 0x1Cu, 0x2Bu, 0x76u, 0xA7u, 0xBCu, 0x25u, 0xE7u, 0x70u,
            0x2Au, 0x70u, 0x4Fu, 0xA9u, 0x86u, 0x89u, 0x28u, 0x49u,
            0xFCu, 0xA6u, 0x29u, 0x48u, 0x7Au, 0xCFu, 0x37u, 0x09u,
            0xD2u, 0xE4u, 0xE8u, 0xBBu
};

/* X9.63-KDF/SHA-256 with Z = K.x||K.y, SharedInfo = 0x02 (msgGrpId 2). */
static const uint8 seclib_st_kdf16_02[16u] =
{
    0xDCu, 0x6Fu, 0x2Bu, 0xEDu, 0x28u, 0x60u, 0x6Du, 0xB9u,
    0x0Au, 0x8Bu, 0xB0u, 0x04u, 0xD9u, 0x86u, 0xE3u, 0x23u
};

static const uint8 seclib_st_kdf28_02[28u] =
{
    0xDCu, 0x6Fu, 0x2Bu, 0xEDu, 0x28u, 0x60u, 0x6Du, 0xB9u,
    0x0Au, 0x8Bu, 0xB0u, 0x04u, 0xD9u, 0x86u, 0xE3u, 0x23u,
    0xD9u, 0x0Au, 0x6Eu, 0xB0u, 0x62u, 0x01u, 0x80u, 0xF8u,
    0xEFu, 0xD4u, 0xB4u, 0xE1u
};

static const uint8 seclib_st_kdf64_02[64u] =
{
    0xDCu, 0x6Fu, 0x2Bu, 0xEDu, 0x28u, 0x60u, 0x6Du, 0xB9u,
    0x0Au, 0x8Bu, 0xB0u, 0x04u, 0xD9u, 0x86u, 0xE3u, 0x23u,
    0xD9u, 0x0Au, 0x6Eu, 0xB0u, 0x62u, 0x01u, 0x80u, 0xF8u,
    0xEFu, 0xD4u, 0xB4u, 0xE1u, 0xE9u, 0xA1u, 0x25u, 0x99u,
    0xE1u, 0xF5u, 0xABu, 0xD4u, 0xF3u, 0x28u, 0x66u, 0xEFu,
    0x5Fu, 0x7Bu, 0x53u, 0x3Bu, 0xC3u, 0xC6u, 0xB0u, 0xD4u,
    0x23u, 0xB3u, 0xB5u, 0x96u, 0x6Du, 0x69u, 0x02u, 0x99u,
    0xBBu, 0xE4u, 0xA7u, 0xDDu, 0x82u, 0x9Au, 0xB2u, 0x52u
};

/* Public key of a point NOT on P-224 (y incremented from a valid one). */
static const uint8 seclib_st_Q_invalid[56u] =
{
    /* x */ 0x25u, 0xC0u, 0xE8u, 0x50u, 0x3Cu, 0xDBu, 0x5Bu, 0x59u,
            0x3Au, 0x78u, 0x7Cu, 0x85u, 0xB2u, 0x75u, 0xC7u, 0x62u,
            0x8Du, 0x0Bu, 0x84u, 0xD6u, 0x12u, 0xA3u, 0xF1u, 0x51u,
            0xA5u, 0x8Du, 0xFEu, 0xD5u,
    /* y = QA.y + 1 */
            0x2Bu, 0xCEu, 0xF2u, 0xC9u, 0xB6u, 0x79u, 0x7Eu, 0xCCu,
            0x0Cu, 0xCFu, 0x2Bu, 0xE8u, 0x82u, 0x17u, 0xFFu, 0x9Au,
            0xB6u, 0xADu, 0xFDu, 0xBCu, 0x78u, 0xB2u, 0xCFu, 0x72u,
            0x68u, 0x40u, 0x1Cu, 0x11u
};

/******************************************************************************/
/*                             LOCAL FUNCTIONS                                 */
/******************************************************************************/
static boolean seclib_st_cmp(const uint8 *a, const uint8 *b, uint32 len)
{
    uint32 i;
    uint8 diff = 0u;

    for (i = 0u; i < len; i++)
    {
        diff |= (uint8)(a[i] ^ b[i]);
    }

    return (diff == 0u) ? TRUE : FALSE;
}

/* Sets the failure output and returns FALSE exactly once per failure. */
static boolean seclib_st_fail(uint32 testId, uint32 *pFailedTest)
{
    if (pFailedTest != NULL)
    {
        *pFailedTest = testId;
    }
    return FALSE;
}

/******************************************************************************/
/*                             GLOBAL FUNCTIONS                                 */
/******************************************************************************/
boolean SecLib_EccSelfTest(uint32 *pFailedTest)
{
    uint8 out[SECLIB_ECC_KDF_OUT_MAX];
    uint8 pub[SECLIB_ECC_PUBKEY_LEN];
    uint8 priv[SECLIB_ECC_PRIVKEY_LEN];
    uint32 i;

    /* ---- SHA-256 KAT via the KDF with zero-length SharedInfo ---- */
    if (SecLib_EccKdfX963Sha256(seclib_st_sha256_msg, sizeof(seclib_st_sha256_msg),
                                NULL, 0u, out, 32u) != OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_SHA256_KAT, pFailedTest);
    }
    if (!seclib_st_cmp(out, seclib_st_sha256_expect, 32u))
    {
        return seclib_st_fail(SECLIB_ECC_ST_SHA256_KAT, pFailedTest);
    }

    /* ---- KDF 16 / 28 / 64 bytes, Z = shared point x||y, SI = 0x02 ---- */
    if (SecLib_EccKdfX963Sha256(seclib_st_K, sizeof(seclib_st_K),
                                (const uint8 *)"\x02", 1u, out, 16u) != OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_KDF_16B, pFailedTest);
    }
    if (!seclib_st_cmp(out, seclib_st_kdf16_02, 16u))
    {
        return seclib_st_fail(SECLIB_ECC_ST_KDF_16B, pFailedTest);
    }

    if (SecLib_EccKdfX963Sha256(seclib_st_K, sizeof(seclib_st_K),
                                (const uint8 *)"\x02", 1u, out, 28u) != OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_KDF_28B, pFailedTest);
    }
    if (!seclib_st_cmp(out, seclib_st_kdf28_02, 28u))
    {
        return seclib_st_fail(SECLIB_ECC_ST_KDF_28B, pFailedTest);
    }

    if (SecLib_EccKdfX963Sha256(seclib_st_K, sizeof(seclib_st_K),
                                (const uint8 *)"\x02", 1u, out, 64u) != OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_KDF_64B, pFailedTest);
    }
    if (!seclib_st_cmp(out, seclib_st_kdf64_02, 64u))
    {
        return seclib_st_fail(SECLIB_ECC_ST_KDF_64B, pFailedTest);
    }

    /* ---- KDF parameter rejection ---- */
    if ((SecLib_EccKdfX963Sha256(seclib_st_K, 0u, NULL, 0u, out, 16u) == OPERATION_SUCCESSFUL) ||
        (SecLib_EccKdfX963Sha256(seclib_st_K, sizeof(seclib_st_K), NULL, 0u, out, 0u) == OPERATION_SUCCESSFUL) ||
        (SecLib_EccKdfX963Sha256(seclib_st_K, sizeof(seclib_st_K), NULL, 0u, out, SECLIB_ECC_KDF_OUT_MAX + 1u) == OPERATION_SUCCESSFUL))
    {
        return seclib_st_fail(SECLIB_ECC_ST_KDF_PARAM, pFailedTest);
    }

    /* ---- Scalar mult with base point: 2*G ---- */
    {
        static const uint8 two[28u] =
        {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x02u
        };

        if (SecLib_EccScalarMultBase(two, pub) != OPERATION_SUCCESSFUL)
        {
            return seclib_st_fail(SECLIB_ECC_ST_MULBASE_D2, pFailedTest);
        }
        if (!seclib_st_cmp(pub, seclib_st_2G, sizeof(seclib_st_2G)))
        {
            return seclib_st_fail(SECLIB_ECC_ST_MULBASE_D2, pFailedTest);
        }
    }

    /* ---- Scalar mult with base point: dA*G = QA ---- */
    if (SecLib_EccScalarMultBase(seclib_st_dA, pub) != OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_MULBASE_DA, pFailedTest);
    }
    if (!seclib_st_cmp(pub, seclib_st_QA, sizeof(seclib_st_QA)))
    {
        return seclib_st_fail(SECLIB_ECC_ST_MULBASE_DA, pFailedTest);
    }

    /* ---- Generic scalar mult: dA*QB = K.x||K.y ---- */
    if (SecLib_EccScalarMultPoint(seclib_st_dA, seclib_st_QB, pub) != OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_MULPOINT, pFailedTest);
    }
    if (!seclib_st_cmp(pub, seclib_st_K, sizeof(seclib_st_K)))
    {
        return seclib_st_fail(SECLIB_ECC_ST_MULPOINT, pFailedTest);
    }

    /* ---- ECDH known answer, both directions ---- */
    if (SecLib_EccComputeSharedSecret(seclib_st_dA, seclib_st_QB, pub) != OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_ECDH_A, pFailedTest);
    }
    if (!seclib_st_cmp(pub, seclib_st_K, sizeof(seclib_st_K)))
    {
        return seclib_st_fail(SECLIB_ECC_ST_ECDH_A, pFailedTest);
    }

    if (SecLib_EccComputeSharedSecret(seclib_st_dB, seclib_st_QA, pub) != OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_ECDH_B, pFailedTest);
    }
    if (!seclib_st_cmp(pub, seclib_st_K, sizeof(seclib_st_K)))
    {
        return seclib_st_fail(SECLIB_ECC_ST_ECDH_B, pFailedTest);
    }

    /* ---- Invalid-curve rejection ---- */
    if (SecLib_EccComputeSharedSecret(seclib_st_dA, seclib_st_Q_invalid, pub) == OPERATION_SUCCESSFUL)
    {
        return seclib_st_fail(SECLIB_ECC_ST_INVALID_CURVE, pFailedTest);
    }

    /* ---- Key generation consistency (RNG-dependent) ----
     * Generate an ephemeral pair, then verify pub == priv*G by recomputing. */
    for (i = 0u; i < 4u; i++)
    {
        if (SecLib_EccGenerateEphemeralKey(priv, pub) != OPERATION_SUCCESSFUL)
        {
            return seclib_st_fail(SECLIB_ECC_ST_KEYGEN_CONSISTENCY, pFailedTest);
        }

        /* priv must not be all-zero and must not equal a previous value. */
        {
            uint32 z;
            uint8 acc = 0u;
            for (z = 0u; z < SECLIB_ECC_PRIVKEY_LEN; z++)
            {
                acc |= priv[z];
            }
            if (acc == 0u)
            {
                return seclib_st_fail(SECLIB_ECC_ST_KEYGEN_CONSISTENCY, pFailedTest);
            }
        }

        if (SecLib_EccScalarMultBase(priv, out) != OPERATION_SUCCESSFUL)
        {
            return seclib_st_fail(SECLIB_ECC_ST_KEYGEN_CONSISTENCY, pFailedTest);
        }
        if (!seclib_st_cmp(out, pub, sizeof(pub)))
        {
            return seclib_st_fail(SECLIB_ECC_ST_KEYGEN_CONSISTENCY, pFailedTest);
        }
    }

    return TRUE;
}
