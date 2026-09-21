/*
 * SecOC adapter for the existing SecurityLib MAC implementation.
 *
 * This adapter is intentionally separate from the generated CSM source. It
 * bridges a committed vKeyM_MPKA CSM message-group key to the existing
 * SecurityLib KEY_RAM-based AES-CMAC functions.
 *
 * Security boundary:
 * - the final CSM key must be readable through Csm_KeyElementGet();
 * - the key is copied through CPU RAM and loaded into ICUS KEY_RAM;
 * - KEY_RAM must not be concurrently used for another security purpose;
 * - this is therefore an integration compatibility path, not an opaque HSM
 *   key path.
 */
#ifndef SECOC_SECURITYLIB_CSM_WRAPPER_H
#define SECOC_SECURITYLIB_CSM_WRAPPER_H

#include "Std_Types.h"
#include "Csm.h"
#include "crypto_library.h"

#define SECOC_SECURITYLIB_PROFILE2_MAC_BITS       (24u)
#define SECOC_SECURITYLIB_PROFILE2_MAC_BYTES      (3u)
#define SECOC_SECURITYLIB_AES128_KEY_BYTES        (16u)
#define SECOC_SECURITYLIB_DATA_ID_BYTES           (2u)
#define SECOC_SECURITYLIB_AUTHENTIC_PDU_BYTES     (5u)
#define SECOC_SECURITYLIB_SECURED_PDU_BYTES       (8u)
#define SECOC_SECURITYLIB_DATA_TO_AUTH_BYTES      (7u)

typedef struct
{
  /* CddMsgGrpId. This integration is intentionally bound to value 2. */
  uint32 messageGroupId;

  /* Generated CSM key ID of vKeyM_MPKA CddMsgGrpKey. */
  uint32 finalMessageGroupCsmKeyId;

  /* Explicit presence flags avoid treating generated handle 0 as invalid. */
  boolean macGenerateJobPresent;
  boolean macVerifyJobPresent;

  /* Generated CSM job IDs used by the SecOC TX/RX processing entries. */
  uint32 macGenerateJobId;
  uint32 macVerifyJobId;
} SecOcSecurityLibMessageGroupConfigType;

/*
 * Registers the generated CSM key/job handles for CddMsgGrpId 2. This must be
 * called during initialization before the CSM dispatch hook is used. It does
 * not activate the key; MAC requests remain fail-closed until activation.
 */
Std_ReturnType SecOcSecurityLib_ConfigureMessageGroup(
  P2CONST(SecOcSecurityLibMessageGroupConfigType, AUTOMATIC, CSM_APPL_VAR) configPtr);

/*
 * Extracts the committed CddMsgGrpKey and activates it in KEY_RAM.
 *
 * The source key element must be CRYPTO_KE_MAC_KEY and exactly 16 bytes. The
 * function returns E_NOT_OK when the key is not readable, invalid, or when
 * KEY_RAM loading is unavailable in this build. Call this only from the
 * successful vKeyM_MPKA finalization path for CddMsgGrpId 2.
 */
Std_ReturnType SecOcSecurityLib_ActivateMessageGroupKey(
  P2CONST(SecOcSecurityLibMessageGroupConfigType, AUTOMATIC, CSM_APPL_VAR) configPtr);

/* Fail closed for subsequent SecOC MAC requests. This does not erase KEY_RAM. */
void SecOcSecurityLib_DeactivateMessageGroupKey(void);

/* Returns TRUE only after a successful key activation. */
boolean SecOcSecurityLib_IsMessageGroupKeyActive(void);

/* Used by the CSM shim to select only the two generated SecOC jobs. */
boolean SecOcSecurityLib_IsMacGenerateJob(uint32 jobId);
boolean SecOcSecurityLib_IsMacVerifyJob(uint32 jobId);

/*
 * Adapter bodies to be called from the project-specific Csm_MacGenerate and
 * Csm_MacVerify integration hook. Do not call Csm_MacGenerate or
 * Csm_MacVerify from these functions; that would recurse.
 */
Std_ReturnType SecOcSecurityLib_CsmMacGenerate(
  uint32 jobId,
  Crypto_OperationModeType mode,
  P2CONST(uint8, AUTOMATIC, CSM_APPL_VAR) dataPtr,
  uint32 dataLength,
  P2VAR(uint8, AUTOMATIC, CSM_APPL_VAR) macPtr,
  P2VAR(uint32, AUTOMATIC, CSM_APPL_VAR) macLengthPtr);

Std_ReturnType SecOcSecurityLib_CsmMacVerify(
  uint32 jobId,
  Crypto_OperationModeType mode,
  P2CONST(uint8, AUTOMATIC, CSM_APPL_VAR) dataPtr,
  uint32 dataLength,
  P2CONST(uint8, AUTOMATIC, CSM_APPL_VAR) macPtr,
  uint32 macLength,
  P2VAR(Crypto_VerifyResultType, AUTOMATIC, CSM_APPL_VAR) verifyPtr);

#endif /* SECOC_SECURITYLIB_CSM_WRAPPER_H */
