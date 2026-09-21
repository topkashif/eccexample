/*
 * Compatibility bridge between Vector SecOC/CSM and the existing SecurityLib.
 *
 * This file deliberately does not replace generated Csm.c. It provides the
 * project integration boundary used by the existing application-side CSM
 * wrapper. If the standard generated Csm_MacGenerate/Csm_MacVerify functions
 * are retained, call these functions from the project-specific dispatch hook;
 * do not define a second Csm API with the same symbol names.
 */
#include "secoc_securitylib_csm_wrapper.h"

#include "Csm.h"

#ifndef SECOC_SECURITYLIB_MESSAGE_GROUP_ID
# define SECOC_SECURITYLIB_MESSAGE_GROUP_ID       (2u) /* CddMsgGrpId */
#endif

#define SECOC_SECURITYLIB_KEY_ELEMENT_ID       (CRYPTO_KE_MAC_KEY)

static boolean SecOcSecurityLib_KeyActive = FALSE;
static boolean SecOcSecurityLib_Configured = FALSE;
static uint32 SecOcSecurityLib_ActiveMessageGroupId = 0u;
static uint32 SecOcSecurityLib_ConfiguredMacGenerateJobId = 0u;
static uint32 SecOcSecurityLib_ConfiguredMacVerifyJobId = 0u;
static boolean SecOcSecurityLib_ConfiguredMacGenerateJobPresent = FALSE;
static boolean SecOcSecurityLib_ConfiguredMacVerifyJobPresent = FALSE;

Std_ReturnType SecOcSecurityLib_ConfigureMessageGroup(
  P2CONST(SecOcSecurityLibMessageGroupConfigType, AUTOMATIC, CSM_APPL_VAR) configPtr)
{
  if ((configPtr == NULL_PTR)
    || (configPtr->messageGroupId != SECOC_SECURITYLIB_MESSAGE_GROUP_ID)
    || ((configPtr->macGenerateJobPresent == TRUE)
      && (configPtr->macVerifyJobPresent == TRUE)
      && (configPtr->macGenerateJobId == configPtr->macVerifyJobId)))
  {
    return E_NOT_OK;
  }

  SecOcSecurityLib_ConfiguredMacGenerateJobId = configPtr->macGenerateJobId;
  SecOcSecurityLib_ConfiguredMacVerifyJobId = configPtr->macVerifyJobId;
  SecOcSecurityLib_ConfiguredMacGenerateJobPresent = configPtr->macGenerateJobPresent;
  SecOcSecurityLib_ConfiguredMacVerifyJobPresent = configPtr->macVerifyJobPresent;
  SecOcSecurityLib_Configured = TRUE;
  SecOcSecurityLib_KeyActive = FALSE;
  return E_OK;
}

static Std_ReturnType SecOcSecurityLib_ValidateMacLengthForGenerate(
  P2CONST(uint8, AUTOMATIC, CSM_APPL_VAR) macPtr,
  P2VAR(uint32, AUTOMATIC, CSM_APPL_VAR) macLengthPtr)
{
  if ((macPtr == NULL_PTR) || (macLengthPtr == NULL_PTR))
  {
    return E_NOT_OK;
  }

  /* Existing SecurityLib generation uses bytes. */
  if (*macLengthPtr < SECOC_SECURITYLIB_PROFILE2_MAC_BYTES)
  {
    return E_NOT_OK;
  }

  return E_OK;
}

static Std_ReturnType SecOcSecurityLib_ValidateMacLengthForVerify(
  P2CONST(uint8, AUTOMATIC, CSM_APPL_VAR) macPtr,
  uint32 macLength)
{
  /* CSM verification receives the length in bits. */
  if ((macPtr == NULL_PTR)
    || (macLength != SECOC_SECURITYLIB_PROFILE2_MAC_BITS))
  {
    return E_NOT_OK;
  }

  return E_OK;
}

Std_ReturnType SecOcSecurityLib_ActivateMessageGroupKey(
  P2CONST(SecOcSecurityLibMessageGroupConfigType, AUTOMATIC, CSM_APPL_VAR) configPtr)
{
  uint8 keyBytes[SECOC_SECURITYLIB_AES128_KEY_BYTES] = {0u};
  uint32 keyLength = SECOC_SECURITYLIB_AES128_KEY_BYTES;
  Std_ReturnType retVal = E_NOT_OK;
  uint8 index;

  if ((configPtr == NULL_PTR)
    || (configPtr->messageGroupId != SECOC_SECURITYLIB_MESSAGE_GROUP_ID)
    || (SecOcSecurityLib_Configured == FALSE)
    || (configPtr->macVerifyJobPresent == FALSE)
    || (SecOcSecurityLib_ConfiguredMacVerifyJobPresent == FALSE)
    || (SecOcSecurityLib_ConfiguredMacVerifyJobId != configPtr->macVerifyJobId)
    || ((configPtr->macGenerateJobPresent == TRUE)
      && (SecOcSecurityLib_ConfiguredMacGenerateJobPresent == FALSE))
    || ((configPtr->macGenerateJobPresent == TRUE)
      && (SecOcSecurityLib_ConfiguredMacGenerateJobId != configPtr->macGenerateJobId)))
  {
    return E_NOT_OK;
  }

  /*
   * The final CddMsgGrpKey must already be committed and valid. This
   * compatibility route requires read access to CRYPTO_KE_MAC_KEY. If the
   * generated MPKA key is deliberately non-readable, use the standard CSM
   * job-to-key route instead; do not use this adapter.
   */
  retVal = Csm_KeyElementGet(
    configPtr->finalMessageGroupCsmKeyId,
    SECOC_SECURITYLIB_KEY_ELEMENT_ID,
    keyBytes,
    &keyLength);

  if ((retVal == E_OK)
    && (keyLength == SECOC_SECURITYLIB_AES128_KEY_BYTES))
  {
    retVal = SecLib_KeyRAMUpdate(keyBytes, (uint8)keyLength);
  }

  /* Do not leave plaintext key material in the adapter stack frame. */
  for (index = 0u; index < SECOC_SECURITYLIB_AES128_KEY_BYTES; index++)
  {
    keyBytes[index] = 0u;
  }

  if (retVal == E_OK)
  {
    SecOcSecurityLib_ActiveMessageGroupId = configPtr->messageGroupId;
    SecOcSecurityLib_KeyActive = TRUE;
  }
  else
  {
    SecOcSecurityLib_KeyActive = FALSE;
    SecOcSecurityLib_ActiveMessageGroupId = 0u;
  }

  return retVal;
}

void SecOcSecurityLib_DeactivateMessageGroupKey(void)
{
  SecOcSecurityLib_ActiveMessageGroupId = 0u;
  SecOcSecurityLib_KeyActive = FALSE;
}

boolean SecOcSecurityLib_IsMessageGroupKeyActive(void)
{
  return SecOcSecurityLib_KeyActive;
}

boolean SecOcSecurityLib_IsMacGenerateJob(uint32 jobId)
{
  return (boolean)((SecOcSecurityLib_Configured == TRUE)
    && (SecOcSecurityLib_ConfiguredMacGenerateJobPresent == TRUE)
    && (jobId == SecOcSecurityLib_ConfiguredMacGenerateJobId));
}

boolean SecOcSecurityLib_IsMacVerifyJob(uint32 jobId)
{
  return (boolean)((SecOcSecurityLib_Configured == TRUE)
    && (SecOcSecurityLib_ConfiguredMacVerifyJobPresent == TRUE)
    && (jobId == SecOcSecurityLib_ConfiguredMacVerifyJobId));
}

Std_ReturnType SecOcSecurityLib_CsmMacGenerate(
  uint32 jobId,
  Crypto_OperationModeType mode,
  P2CONST(uint8, AUTOMATIC, CSM_APPL_VAR) dataPtr,
  uint32 dataLength,
  P2VAR(uint8, AUTOMATIC, CSM_APPL_VAR) macPtr,
  P2VAR(uint32, AUTOMATIC, CSM_APPL_VAR) macLengthPtr)
{
  uint32 generatedLength;
  Enable_Secure_Boot_Status_Type status;

  if (mode != CRYPTO_OPERATIONMODE_SINGLECALL)
  {
    return E_NOT_OK;
  }

  if ((SecOcSecurityLib_KeyActive == FALSE)
    || (SecOcSecurityLib_ActiveMessageGroupId != SECOC_SECURITYLIB_MESSAGE_GROUP_ID)
    || (!SecOcSecurityLib_IsMacGenerateJob(jobId))
    || (dataPtr == NULL_PTR)
    || (dataLength != SECOC_SECURITYLIB_DATA_TO_AUTH_BYTES)
    || (SecOcSecurityLib_ValidateMacLengthForGenerate(macPtr, macLengthPtr) != E_OK))
  {
    return E_NOT_OK;
  }

  /*
   * SecOC lessons 0002/0005/0006 define:
   *   Data ID 02 02 (2 bytes) + Authentic PDU (5 bytes) = 7 bytes.
   * Request only the three transmitted bytes so the legacy generator cannot
   * write a 16-byte CMAC into a three-byte SecOC buffer.
   */
  generatedLength = SECOC_SECURITYLIB_PROFILE2_MAC_BYTES;
  status = SecLib_MACGenerate(
    KEY_RAM,
    dataPtr,
    dataLength,
    macPtr,
    &generatedLength);

  if ((status != OPERATION_SUCCESSFUL)
    || (generatedLength < SECOC_SECURITYLIB_PROFILE2_MAC_BYTES))
  {
    return E_NOT_OK;
  }

  *macLengthPtr = SECOC_SECURITYLIB_PROFILE2_MAC_BYTES;
  return E_OK;
}

Std_ReturnType SecOcSecurityLib_CsmMacVerify(
  uint32 jobId,
  Crypto_OperationModeType mode,
  P2CONST(uint8, AUTOMATIC, CSM_APPL_VAR) dataPtr,
  uint32 dataLength,
  P2CONST(uint8, AUTOMATIC, CSM_APPL_VAR) macPtr,
  uint32 macLength,
  P2VAR(Crypto_VerifyResultType, AUTOMATIC, CSM_APPL_VAR) verifyPtr)
{
  Enable_Secure_Boot_Status_Type status;

  if (mode != CRYPTO_OPERATIONMODE_SINGLECALL)
  {
    if (verifyPtr != NULL_PTR)
    {
      *verifyPtr = CSM_E_VER_NOT_OK;
    }
    return E_NOT_OK;
  }

  if (verifyPtr != NULL_PTR)
  {
    *verifyPtr = CSM_E_VER_NOT_OK;
  }

  if ((SecOcSecurityLib_KeyActive == FALSE)
    || (SecOcSecurityLib_ActiveMessageGroupId != SECOC_SECURITYLIB_MESSAGE_GROUP_ID)
    || (!SecOcSecurityLib_IsMacVerifyJob(jobId))
    || (dataPtr == NULL_PTR)
    || (dataLength != SECOC_SECURITYLIB_DATA_TO_AUTH_BYTES)
    || (SecOcSecurityLib_ValidateMacLengthForVerify(macPtr, macLength) != E_OK)
    || (verifyPtr == NULL_PTR))
  {
    return E_NOT_OK;
  }

  /* Existing SecurityLib verification consumes the MAC length in bytes. */
  status = SecLib_MACVerify(
    KEY_RAM,
    dataPtr,
    dataLength,
    macPtr,
    SECOC_SECURITYLIB_PROFILE2_MAC_BYTES);

  if (status == OPERATION_SUCCESSFUL)
  {
    *verifyPtr = CSM_E_VER_OK;
    return E_OK;
  }

  /* A completed CMAC comparison with a non-matching MAC is not a CSM
   * transport/driver failure. Preserve E_OK and report the comparison result
   * through verifyPtr so SecOC can classify it as authentication failure. */
  if (status == E_CMAC_VERIFY_ERROR)
  {
    *verifyPtr = CSM_E_VER_NOT_OK;
    return E_OK;
  }

  *verifyPtr = CSM_E_VER_NOT_OK;
  return E_NOT_OK;
}
