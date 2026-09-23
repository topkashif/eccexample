/* ===========================================================================**
**                                                                            **
**  Modulo:            SecLib_Ecc                                             **
**                                                                            **
**  Description:       ECC extension of SecurityLib for vKeyM_MPKA key        **
**                     negotiation (CS.00172 Diffie-Hellman, FIPS P-224 /     **
**                     secp224r1). See seclib_ecc.h for the full contract.    **
**                                                                            **
**  Implementation:    mbedtls ECP (2.27.0 port) on the project bignum fork.  **
**                     Coordinates are exchanged as fixed 28-byte big-endian  **
**                     values; the uncompressed wire point is X || Y (56 B)   **
**                     without the 0x04 prefix (vKeyM_MPKA wire format).      **
******************************************************************************/
/******************************************************************************/
/*                                INCLUDES                                     */
/******************************************************************************/
#include "seclib_ecc.h"
#include "crypto_library.h"

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/sha256.h"

#include <stdlib.h>
#include <string.h>

/* Runtime allocator binding (see seclib_ecc_bind_allocator): the dispatch
 * function mbedtls_platform_set_calloc_free() exists only when the platform
 * layer is compiled with the runtime allocation configuration and no
 * compile-time macros override it. Nested #if directives avoid
 * line-continuations. */
#if defined(MBEDTLS_PLATFORM_MEMORY)
#if !defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
#if !defined(MBEDTLS_PLATFORM_FREE_MACRO)
#include "mbedtls/platform.h"
#define SECLIB_ECC_BIND_ALLOCATOR
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#define SECLIB_ECC_USE_STATIC_POOL
#endif
#endif
#endif
#endif

/******************************************************************************/
/*                                LOCAL DATA                                   */
/******************************************************************************/
/* P-224 domain parameters, loaded once by SecLib_EccInit().
 * Contains no secret material; wiped on demand by SecLib_EccWipeState(). */
static mbedtls_ecp_group seclib_ecc_grp;

static boolean seclib_ecc_initialized = FALSE;

/* Dedicated heap for the ECC mbedtls layer (see seclib_ecc_bind_allocator).
 * Sizing: P-224 with MBEDTLS_ECP_WINDOW_SIZE = 3 and
 * MBEDTLS_ECP_FIXED_POINT_OPTIM = 0 peaks below 1 KiB (window table
 * ~336 B plus mpi temporaries); 2 KiB covers it with margin. A static pool
 * keeps ECC independent of the C-library heap and of the SecuritySAM token
 * buffer (SecuritySMCore memory_buf), which share the global allocator
 * dispatch in platform.c. */
#ifdef SECLIB_ECC_USE_STATIC_POOL
#define SECLIB_ECC_HEAP_SIZE (2048u)
static uint8 seclib_ecc_heap[SECLIB_ECC_HEAP_SIZE];
#endif

/******************************************************************************/
/*                             LOCAL FUNCTIONS                                 */
/******************************************************************************/

/* Bind the mbedtls heap allocator dispatch (platform.c function pointers) to
 * this module's own static pool. bignum and ECP perform every heap allocation
 * through the global dispatch when the runtime allocation configuration
 * (MBEDTLS_PLATFORM_C + MBEDTLS_PLATFORM_MEMORY) is compiled in; the project
 * rebinds that global pointer at runtime (SecuritySAM token buffer via
 * SecuritySMCore, C-library heap otherwise), so ECC binds its own pool at
 * every public entry point. Its allocations then stay deterministic and
 * bounded: an exhausted pool yields NULL from mbedtls_calloc and a clean
 * MBEDTLS_ERR_MPI_ALLOC_FAILED, never a fault.
 * Concurrency: ECC and the SAM install flow must not interleave (they would
 * rebind the shared dispatch under each other); this matches the existing
 * ICUS single-service rule that already forbids concurrent crypto contexts. */
#ifdef SECLIB_ECC_USE_STATIC_POOL
static void seclib_ecc_bind_allocator(void)
{
    mbedtls_memory_buffer_alloc_init( seclib_ecc_heap, SECLIB_ECC_HEAP_SIZE );
}
#else
static void seclib_ecc_bind_allocator(void)
{
#ifdef SECLIB_ECC_BIND_ALLOCATOR
    /* Runtime dispatch without the pool allocator: bind the C library. */
    (void)mbedtls_platform_set_calloc_free( calloc, free );
#else
    /* Compile-time allocator binding (MBEDTLS_PLATFORM_*_MACRO, or no
     * MBEDTLS_PLATFORM_MEMORY): mbedtls_calloc is a direct macro and the
     * dispatch pointers in platform.c do not exist. Nothing to bind. */
#endif
}
#endif

/* RNG bridge: mbedtls f_rng signature -> SecLib_RandomGenerate (ICUS PRNG
 * through the generated Csm random service). The ICUS RNG primitive produces
 * at most RNG_BYTE_SIZE (16) bytes per call and SecLib_RandomGenerate
 * enforces exactly that length, so requests are served in 16-byte chunks. */
#if defined(SECLIB_ECC_BENCH_NO_ICUS)
/* ----------------------------------------------------------------------------
 * BENCH-ONLY deterministic RNG (32-bit xorshift).
 *
 * Purpose: run SecLib_EccSelfTest on an ECU/bench build where ICUS is not
 * yet enabled. All KAT results are independent of the RNG values (the RNG is
 * used only for coordinate blinding, which does not change the mathematical
 * result, and for the keygen consistency test, which validates structure,
 * not entropy).
 *
 * SECURITY: output is fully predictable. NEVER define SECLIB_ECC_BENCH_NO_ICUS
 * in a production or security-relevant build; production must use the ICUS
 * PRNG branch below. Keep this macro undefined (default).
 * -------------------------------------------------------------------------- */
static uint32 seclib_ecc_bench_rng_state = 0x1A2B3C4Du;

static int seclib_ecc_rng_cb(void *p_rng, unsigned char *out, size_t out_len)
{
    size_t i;
    uint32 x = seclib_ecc_bench_rng_state;

    (void)p_rng;

    if (out == NULL)
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    for (i = 0u; i < out_len; i++)
    {
        /* xorshift32: period 2^32-1, deterministic, bench-only */
        x ^= (uint32)(x << 13u);
        x ^= (uint32)(x >> 17u);
        x ^= (uint32)(x << 5u);
        seclib_ecc_bench_rng_state = x;
        out[i] = (uint8)(x & 0xFFu);
    }

    return 0;
}
#else
static int seclib_ecc_rng_cb(void *p_rng, unsigned char *out, size_t out_len)
{
    uint8 chunk[RNG_BYTE_SIZE];
    size_t filled = 0u;
    size_t take;

    (void)p_rng;

    if (out == NULL)
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    while (filled < out_len)
    {
        if (SecLib_RandomGenerate(chunk, RNG_BYTE_SIZE) != OPERATION_SUCCESSFUL)
        {
            memset(chunk, 0, sizeof(chunk));
            return MBEDTLS_ERR_ECP_RANDOM_FAILED;
        }

        take = out_len - filled;
        if (take > RNG_BYTE_SIZE)
        {
            take = RNG_BYTE_SIZE;
        }
        memcpy(&out[filled], chunk, take);
        filled += take;

        /* The tail of the last chunk beyond out_len is unused entropy:
         * do not leave it on the stack. */
        memset(chunk, 0, sizeof(chunk));
    }

    return 0;
}
#endif /* SECLIB_ECC_BENCH_NO_ICUS */

/* Import a 56-byte X||Y wire point into an mbedtls point (no on-curve check). */
static int seclib_ecc_point_read(const uint8 *buf, mbedtls_ecp_point *P)
{
    int ret;

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &P->X, buf, SECLIB_ECC_COORD_LEN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &P->Y, buf + SECLIB_ECC_COORD_LEN, SECLIB_ECC_COORD_LEN ) );

cleanup:
    return ret;
}

/* Export an mbedtls point as 56-byte X||Y wire point. */
static int seclib_ecc_point_write(const mbedtls_ecp_point *P, uint8 *buf)
{
    int ret;

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->X, buf, SECLIB_ECC_COORD_LEN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->Y, buf + SECLIB_ECC_COORD_LEN, SECLIB_ECC_COORD_LEN ) );

cleanup:
    return ret;
}

/******************************************************************************/
/*                        GLOBAL FUNCTIONS                                     */
/******************************************************************************/

Enable_Secure_Boot_Status_Type SecLib_EccInit(void)
{
    int ret;

    if (seclib_ecc_initialized)
    {
        return OPERATION_SUCCESSFUL;
    }

    seclib_ecc_bind_allocator();

    mbedtls_ecp_group_init( &seclib_ecc_grp );

    ret = mbedtls_ecp_group_load( &seclib_ecc_grp, MBEDTLS_ECP_DP_SECP224R1 );
    if (ret != 0)
    {
        mbedtls_ecp_group_free( &seclib_ecc_grp );
        return OPERATION_GENERAL_ERROR;
    }

    seclib_ecc_initialized = TRUE;
    return OPERATION_SUCCESSFUL;
}

boolean SecLib_EccIsInitialized(void)
{
    return seclib_ecc_initialized;
}

Enable_Secure_Boot_Status_Type SecLib_EccGenerateEphemeralKey(
        uint8 *privKey,
        uint8 *pubKey)
{
    int ret;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    if (!seclib_ecc_initialized)
    {
        return OPERATION_GENERAL_ERROR;
    }
    if ((privKey == NULL) || (pubKey == NULL))
    {
        return OPERATION_GENERAL_ERROR;
    }

    seclib_ecc_bind_allocator();

    mbedtls_mpi_init( &d );
    mbedtls_ecp_point_init( &Q );

    /* d uniform in [1, n-1] (RFC 6979 style, unbiased) - CS.00172 REQ 5.6.1 */
    MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( &seclib_ecc_grp, &d,
                                              seclib_ecc_rng_cb, NULL ) );

    /* Q = d * G - CS.00172 REQ 5.6.2 */
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &seclib_ecc_grp, &Q, &d, &seclib_ecc_grp.G,
                                      seclib_ecc_rng_cb, NULL ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &d, privKey, SECLIB_ECC_PRIVKEY_LEN ) );
    MBEDTLS_MPI_CHK( seclib_ecc_point_write( &Q, pubKey ) );

cleanup:
    /* Erase the private scalar from RAM on every exit path. */
    mbedtls_mpi_free( &d );
    mbedtls_ecp_point_free( &Q );

    return (ret == 0) ? OPERATION_SUCCESSFUL : OPERATION_GENERAL_ERROR;
}

Enable_Secure_Boot_Status_Type SecLib_EccScalarMultBase(
        const uint8 *scalar,
        uint8 *outPoint)
{
    int ret;
    mbedtls_mpi k;
    mbedtls_ecp_point Q;

    if (!seclib_ecc_initialized)
    {
        return OPERATION_GENERAL_ERROR;
    }
    if ((scalar == NULL) || (outPoint == NULL))
    {
        return OPERATION_GENERAL_ERROR;
    }

    seclib_ecc_bind_allocator();

    mbedtls_mpi_init( &k );
    mbedtls_ecp_point_init( &Q );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &k, scalar, SECLIB_ECC_PRIVKEY_LEN ) );

    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &seclib_ecc_grp, &Q, &k, &seclib_ecc_grp.G,
                                      seclib_ecc_rng_cb, NULL ) );

    MBEDTLS_MPI_CHK( seclib_ecc_point_write( &Q, outPoint ) );

cleanup:
    mbedtls_mpi_free( &k );
    mbedtls_ecp_point_free( &Q );

    return (ret == 0) ? OPERATION_SUCCESSFUL : OPERATION_GENERAL_ERROR;
}

Enable_Secure_Boot_Status_Type SecLib_EccScalarMultPoint(
        const uint8 *scalar,
        const uint8 *point,
        uint8 *outPoint)
{
    int ret;
    mbedtls_mpi k;
    mbedtls_ecp_point P;
    mbedtls_ecp_point Q;

    if (!seclib_ecc_initialized)
    {
        return OPERATION_GENERAL_ERROR;
    }
    if ((scalar == NULL) || (point == NULL) || (outPoint == NULL))
    {
        return OPERATION_GENERAL_ERROR;
    }

    seclib_ecc_bind_allocator();

    mbedtls_mpi_init( &k );
    mbedtls_ecp_point_init( &P );
    mbedtls_ecp_point_init( &Q );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &k, scalar, SECLIB_ECC_PRIVKEY_LEN ) );
    MBEDTLS_MPI_CHK( seclib_ecc_point_read( point, &P ) );

    /* Invalid-curve protection: reject points not on P-224. */
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_pubkey( &seclib_ecc_grp, &P ) );

    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &seclib_ecc_grp, &Q, &k, &P,
                                      seclib_ecc_rng_cb, NULL ) );

    MBEDTLS_MPI_CHK( seclib_ecc_point_write( &Q, outPoint ) );

cleanup:
    mbedtls_mpi_free( &k );
    mbedtls_ecp_point_free( &P );
    mbedtls_ecp_point_free( &Q );

    return (ret == 0) ? OPERATION_SUCCESSFUL : OPERATION_GENERAL_ERROR;
}

Enable_Secure_Boot_Status_Type SecLib_EccComputeSharedSecret(
        const uint8 *privKey,
        const uint8 *peerPubKey,
        uint8 *sharedSecret)
{
    int ret;
    mbedtls_mpi d;
    mbedtls_ecp_point Qp;
    mbedtls_ecp_point K;

    if (!seclib_ecc_initialized)
    {
        return OPERATION_GENERAL_ERROR;
    }
    if ((privKey == NULL) || (peerPubKey == NULL) || (sharedSecret == NULL))
    {
        return OPERATION_GENERAL_ERROR;
    }

    seclib_ecc_bind_allocator();

    mbedtls_mpi_init( &d );
    mbedtls_ecp_point_init( &Qp );
    mbedtls_ecp_point_init( &K );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &d, privKey, SECLIB_ECC_PRIVKEY_LEN ) );
    MBEDTLS_MPI_CHK( seclib_ecc_point_read( peerPubKey, &Qp ) );

    /* Invalid-curve protection: reject points not on P-224. */
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_pubkey( &seclib_ecc_grp, &Qp ) );

    /* K = d * Q_peer - CS.00172 REQ 5.6.4 */
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &seclib_ecc_grp, &K, &d, &Qp,
                                      seclib_ecc_rng_cb, NULL ) );

    MBEDTLS_MPI_CHK( seclib_ecc_point_write( &K, sharedSecret ) );

cleanup:
    mbedtls_mpi_free( &d );
    mbedtls_ecp_point_free( &Qp );
    mbedtls_ecp_point_free( &K );

    return (ret == 0) ? OPERATION_SUCCESSFUL : OPERATION_GENERAL_ERROR;
}

Enable_Secure_Boot_Status_Type SecLib_EccKdfX963Sha256(
        const uint8 *z,
        uint32 zLen,
        const uint8 *sharedInfo,
        uint32 sharedInfoLen,
        uint8 *out,
        uint32 outLen)
{
    Enable_Secure_Boot_Status_Type retVal = OPERATION_SUCCESSFUL;
    uint32 generated = 0u;
    uint32 counter = 1u;
    uint32 blockLen;
    uint32 remaining;
    uint32 copyLen;
    uint8 block[SECLIB_ECC_SHA256_LEN];
    uint8 counterBe[4u]; /* X9.63: 4-octet big-endian counter */
    mbedtls_sha256_context ctx;

    if ((z == NULL) || (out == NULL) || (zLen == 0u) ||
        (outLen == 0u) || (outLen > SECLIB_ECC_KDF_OUT_MAX) ||
        ((sharedInfo == NULL) && (sharedInfoLen != 0u)))
    {
        return OPERATION_GENERAL_ERROR;
    }

    remaining = outLen;

    while (generated < outLen)
    {
        /* Si = SHA256( Z || Counter || [SharedInfo] ), Counter: 4-byte BE */
        counterBe[0u] = (uint8)(counter >> 24u);
        counterBe[1u] = (uint8)(counter >> 16u);
        counterBe[2u] = (uint8)(counter >> 8u);
        counterBe[3u] = (uint8)(counter);

        mbedtls_sha256_init( &ctx );

        if (mbedtls_sha256_starts_ret( &ctx, 0 ) != 0)
        {
            retVal = OPERATION_GENERAL_ERROR;
            break;
        }
        if ((mbedtls_sha256_update_ret( &ctx, z, zLen ) != 0) ||
            (mbedtls_sha256_update_ret( &ctx, counterBe, 4u ) != 0))
        {
            retVal = OPERATION_GENERAL_ERROR;
        }
        else if ((sharedInfoLen != 0u) &&
                 (mbedtls_sha256_update_ret( &ctx, sharedInfo, sharedInfoLen ) != 0))
        {
            retVal = OPERATION_GENERAL_ERROR;
        }
        else if (mbedtls_sha256_finish_ret( &ctx, block ) != 0)
        {
            retVal = OPERATION_GENERAL_ERROR;
        }
        else
        {
            blockLen = SECLIB_ECC_SHA256_LEN;
            copyLen = (remaining < blockLen) ? remaining : blockLen;

            memcpy( out + generated, block, copyLen );

            generated += copyLen;
            remaining -= copyLen;
            counter++;
        }

        mbedtls_sha256_free( &ctx );

        if (retVal != OPERATION_SUCCESSFUL)
        {
            break;
        }
    }

    /* erase the last hash block from the stack on every exit path */
    memset( block, 0, sizeof(block) );

    return retVal;
}

void SecLib_EccWipeState(void)
{
    if (seclib_ecc_initialized)
    {
        mbedtls_ecp_group_free( &seclib_ecc_grp );
        seclib_ecc_initialized = FALSE;
    }
}
