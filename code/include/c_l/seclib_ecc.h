/* ===========================================================================**
**                                                                            **
**  Modulo:            SecLib_Ecc                                             **
**                                                                            **
**  Description:       ECC extension of SecurityLib for vKeyM_MPKA key        **
**                     negotiation (CS.00172 Diffie-Hellman, FIPS P-224 /     **
**                     secp224r1). Provides ephemeral key generation,         **
**                     scalar multiplication, shared secret derivation and    **
**                     the ANSI X9.63 (SHA-256) key derivation function.      **
**                                                                            **
**  Crypto backend:    mbedtls ECP (ported from 2.27.0), bignum from the      **
**                     project fork; randomness from SecLib_RandomGenerate    **
**                     (ICUS PRNG via generated Csm random service).          **
**                                                                            **
**  Security notes:    - Private keys exist only as stack/heap values and     **
**                       are zeroized on every exit path (no NVM, no SHE      **
**                       slot). This realizes CS.00172 REQ 5.6.1 ("store in   **
**                       the HPSE") as a software-only interpretation, which  **
**                       must be recorded as an assurance deviation for the   **
**                       ICUS platform.                                       **
**                     - Peer public keys are validated to be on the curve    **
**                       before use (invalid-curve protection).               **
**                     - All byte arrays are fixed length, big endian.        **
******************************************************************************/
#ifndef SECLIB_ECC_H
#define SECLIB_ECC_H

/*****************************************************************************/
/**                            INCLUDE                                       *
******************************************************************************/
#include "crypto_library_type.h"

/*****************************************************************************/
/**                            DEFINE                                         *
******************************************************************************/
/* secp224r1 wire sizes (big endian), per CS.00172 and vKeyM_MPKA_Types.h */
#define SECLIB_ECC_PRIVKEY_LEN        (28u)  /* scalar a                        */
#define SECLIB_ECC_PUBKEY_LEN         (56u)  /* uncompressed X || Y             */
#define SECLIB_ECC_COORD_LEN          (28u)  /* single coordinate               */
#define SECLIB_ECC_SHA256_LEN         (32u)  /* KDF hash length                 */
#define SECLIB_ECC_KDF_OUT_MAX        (256u) /* hard bound on KDF output length */

/******************************************************************************/
/**                        PROTOTYPE FUNCTION                                 *
******************************************************************************/

/* One-time initialization: load the P-224 domain parameters.
 * Must be called once before any other SecLib_Ecc function
 * (e.g. from the same init path as SecLib_Init()).
 * @return OPERATION_SUCCESSFUL on success, error code otherwise */
Enable_Secure_Boot_Status_Type SecLib_EccInit(void);

/* Returns TRUE after a successful SecLib_EccInit(). */
boolean SecLib_EccIsInitialized(void);

/* Generate an ephemeral private scalar d in [1, n-1] and the public
 * point Q = d * G. The private key is generated inside this module and
 * must be treated as HPSE-equivalent secret material by the caller.
 * @param  privKey  out: 28-byte private scalar (big endian)
 * @param  pubKey   out: 56-byte public point X || Y (big endian)
 * @return OPERATION_SUCCESSFUL on success, error code otherwise */
Enable_Secure_Boot_Status_Type SecLib_EccGenerateEphemeralKey(
        uint8 *privKey,    /* SECLIB_ECC_PRIVKEY_LEN */
        uint8 *pubKey);    /* SECLIB_ECC_PUBKEY_LEN  */

/* Scalar multiplication with the curve base point: outPoint = k * G.
 * @param  scalar    in: 28-byte scalar (big endian)
 * @param  outPoint  out: 56-byte point X || Y (big endian)
 * @return OPERATION_SUCCESSFUL on success, error code otherwise */
Enable_Secure_Boot_Status_Type SecLib_EccScalarMultBase(
        const uint8 *scalar,   /* SECLIB_ECC_PRIVKEY_LEN */
        uint8 *outPoint);      /* SECLIB_ECC_PUBKEY_LEN  */

/* Generic scalar multiplication: outPoint = k * P.
 * @param  scalar    in: 28-byte scalar (big endian)
 * @param  point     in: 56-byte input point X || Y (big endian),
 *                       must be a valid point on P-224
 * @param  outPoint  out: 56-byte point X || Y (big endian)
 * @return OPERATION_SUCCESSFUL on success, error code otherwise
 * @note   Provided for completeness (CS.00172 "other required features");
 *         the ECDH exchange itself uses SecLib_EccComputeSharedSecret. */
Enable_Secure_Boot_Status_Type SecLib_EccScalarMultPoint(
        const uint8 *scalar,   /* SECLIB_ECC_PRIVKEY_LEN */
        const uint8 *point,    /* SECLIB_ECC_PUBKEY_LEN  */
        uint8 *outPoint);      /* SECLIB_ECC_PUBKEY_LEN  */

/* ECDH shared secret (CS.00172 REQ 5.6.4): K = d * Q_peer.
 * The peer point is validated on-curve before multiplication.
 * @param  privKey      in: 28-byte own private scalar (big endian)
 * @param  peerPubKey   in: 56-byte peer public point X || Y (big endian)
 * @param  sharedSecret out: 56-byte shared point X || Y (big endian)
 * @return OPERATION_SUCCESSFUL on success, error code otherwise */
Enable_Secure_Boot_Status_Type SecLib_EccComputeSharedSecret(
        const uint8 *privKey,     /* SECLIB_ECC_PRIVKEY_LEN */
        const uint8 *peerPubKey,  /* SECLIB_ECC_PUBKEY_LEN  */
        uint8 *sharedSecret);     /* SECLIB_ECC_PUBKEY_LEN  */

/* ANSI X9.63 key derivation function with SHA-256 (CS.00172 REQ 5.7.2):
 *   Si = SHA256( Z || Counter || [SharedInfo] ), Counter = 4-byte big
 *   endian starting at 1; output = leftmost outLen bytes of S1||S2||...
 * The caller selects Z per CS.00172 (x||y of the shared point for the
 * Group Message key) and SharedInfo = 1-byte message group ID.
 * @param  z             in: shared secret byte string
 * @param  zLen          in: length of z in bytes (SECLIB_ECC_PUBKEY_LEN for CS.00172)
 * @param  sharedInfo    in: SharedInfo byte string (may be NULL if sharedInfoLen == 0)
 * @param  sharedInfoLen in: length of SharedInfo in bytes
 * @param  out           out: derived keying data (outLen bytes)
 * @param  outLen        in:  requested output length in bytes,
 *                            1..SECLIB_ECC_KDF_OUT_MAX
 * @return OPERATION_SUCCESSFUL on success, error code otherwise */
Enable_Secure_Boot_Status_Type SecLib_EccKdfX963Sha256(
        const uint8 *z,
        uint32 zLen,
        const uint8 *sharedInfo,
        uint32 sharedInfoLen,
        uint8 *out,
        uint32 outLen);

/* Zeroize all ECC working state held by this module (curve context and
 * any precomputed tables). Call once key negotiation has completed and
 * the derived key has been committed (CS.00172 REQ 5.8.5).
 * After this call SecLib_EccInit() must be invoked again before further
 * use. Per-call secrets (private scalars, points) are already zeroized
 * on each function exit. */
void SecLib_EccWipeState(void);

#endif /* SECLIB_ECC_H */
