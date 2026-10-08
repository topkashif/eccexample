/**********************************************************************************************************************
 *  COPYRIGHT
 *  -------------------------------------------------------------------------------------------------------------------
 *  \verbatim
 *  Copyright (c) 2020 by Vector Informatik GmbH.                                                All rights reserved.
 *
 *                This software is copyright protected and proprietary to Vector Informatik GmbH.
 *                Vector Informatik GmbH grants to you only those rights as set out in the license conditions.
 *                All other rights remain with Vector Informatik GmbH.
 *  \endverbatim
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*      \file  Crypto_30_CryWrapper_Hw.c
 *      \brief  MICROSAR Crypto Driver (Crypto)
 *
 *      \details  Hardware specific functions.
 *
 *********************************************************************************************************************/

/**********************************************************************************************************************
 *  REVISION HISTORY
 *  -------------------------------------------------------------------------------------------------------------------
 *  Refer to the module's header file.
 *********************************************************************************************************************/

#define CRYPTO_30_CRYWRAPPER_HW_SOURCE
/* PRQA S 0777, 0779, 3453 EOF */ /* MD_MSR_5.1_777, MD_MSR_5.1_779, MD_MSR_19.7 */

/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/
#include "Crypto_30_CryWrapper.h"
#include "Crypto_30_CryWrapper_Hw.h"
#include "Crypto_30_CryWrapper_KeyManagement.h"

/* SecurityLib ECC extension: operational P-224/ECDH/X9.63 provider backend */
#include "seclib_ecc.h"

#include <string.h>

#include "CryIf_Cbk.h"

/**********************************************************************************************************************
 *  LOCAL CONSTANT MACROS
 **********************************************************************************************************************/

#define Crypto_30_CryWrapper_IsKeyMLockFree()                         (Crypto_30_CryWrapper_KeyMLocked == FALSE)
#define Crypto_30_CryWrapper_SetKeyMLock()                            (Crypto_30_CryWrapper_KeyMLocked = TRUE)
#define Crypto_30_CryWrapper_FreeKeyMLock()                           (Crypto_30_CryWrapper_KeyMLocked = FALSE)

#define CRYPTO_30_CRYWRAPPER_SHE_KEY_UPDATE_LENGTH                    (64u)
#define CRYPTO_30_CRYWRAPPER_SHE_KEY_UPDATE_LENGTH_WITH_KEYID         (CRYPTO_30_CRYWRAPPER_SHE_KEY_UPDATE_LENGTH + 1u)

#define CRYPTO_30_CRYWRAPPER_OFFSET_KEYID                             (0u)
#define CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE                         (1u)

/**********************************************************************************************************************
 *  LOCAL DATA TYPES AND STRUCTURES
 *********************************************************************************************************************/

#if !defined (CRYPTO_30_CRYWRAPPER_LOCAL) /* COV_CRYPTO_30_CRYWRAPPER_LOCAL_DEFINE */
# define CRYPTO_30_CRYWRAPPER_LOCAL                                   static
#endif

#if !defined (CRYPTO_30_CRYWRAPPER_LOCAL_INLINE) /* COV_CRYPTO_30_CRYWRAPPER_LOCAL_DEFINE */
# define CRYPTO_30_CRYWRAPPER_LOCAL_INLINE                            LOCAL_INLINE
#endif

/**********************************************************************************************************************
 *  LOCAL DATA PROTOTYPES
 **********************************************************************************************************************/

#define CRYPTO_30_CRYWRAPPER_START_SEC_VAR_NOINIT_8BIT
#include "MemMap.h" /* PRQA S 5087 */ /* MD_MSR_19.1 */

 /*! Lock for key management functions */
CRYPTO_30_CRYWRAPPER_LOCAL VAR(boolean, CRYPTO_30_CRYWRAPPER_VAR_NOINIT) Crypto_30_CryWrapper_KeyMLocked;

#define CRYPTO_30_CRYWRAPPER_STOP_SEC_VAR_NOINIT_8BIT
#include "MemMap.h" /* PRQA S 5087 */ /* MD_MSR_19.1 */

#if Crypto_30_CryWrapper_IsRamKeyLifeCycleSupportOfWrapperGeneral()
# define CRYPTO_30_CRYWRAPPER_START_SEC_VAR_NOINIT_UNSPECIFIED
# include "MemMap.h" /* PRQA S 5087 */ /* MD_MSR_19.1 */

/*! Current LifeCycle value of the RAM key */
CRYPTO_30_CRYWRAPPER_LOCAL VAR(Csm_AlignType, CRYPTO_30_CRYWRAPPER_VAR_NOINIT) Crypto_30_CryWrapper_CurrentLifeCycle;

# define CRYPTO_30_CRYWRAPPER_STOP_SEC_VAR_NOINIT_UNSPECIFIED
# include "MemMap.h" /* PRQA S 5087 */ /* MD_MSR_19.1 */
#endif

#define CRYPTO_30_CRYWRAPPER_START_SEC_CONST_UNSPECIFIED
#include "MemMap.h" /* PRQA S 5087 */ /* MD_MSR_19.1 */

CONST(uint8, CRYPTO_30_CRYWRAPPER_CONST) Crypto_30_CryWrapper_MappingTableSheToCryShe[25] =
{
  /* Idx */ /* SHE KeyId */                                         /* Name of Key */
  /* 0   */  0x00u,                                                 /* SECRET_KEY */
  /* 1   */  0x01u,                                                 /* MASTER_ECU_KEY */
  /* 2   */  0x02u,                                                 /* BOOT_MAC_KEY */
  /* 3   */  0x03u,                                                 /* BOOT_MAC */
  /* 4   */  0x04u,                                                 /* KEY_1 */
  /* 5   */  0x05u,                                                 /* KEY_2 */
  /* 6   */  0x06u,                                                 /* KEY_3 */
  /* 7   */  0x07u,                                                 /* KEY_4 */
  /* 8   */  0x08u,                                                 /* KEY_5 */
  /* 9   */  0x09u,                                                 /* KEY_6 */
  /* 10  */  0x0Au,                                                 /* KEY_7 */
  /* 11  */  0x0Bu,                                                 /* KEY_8 */
  /* 12  */  0x0Cu,                                                 /* KEY_9 */
  /* 13  */  0x0Du,                                                 /* KEY_10 */
  /* 14  */  0x0Eu,                                                 /* KEY_RAM */
  /* 15  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x00u,   /* KEY_11 */
  /* 16  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x01u,   /* KEY_12 */
  /* 17  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x02u,   /* KEY_13 */
  /* 18  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x03u,   /* KEY_14 */
  /* 19  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x04u,   /* KEY_15 */
  /* 20  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x05u,   /* KEY_16 */
  /* 21  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x06u,   /* KEY_17 */
  /* 22  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x07u,   /* KEY_18 */
  /* 23  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x08u,   /* KEY_19 */
  /* 24  */  CRYPTO_30_CRYWRAPPER_SECOND_KEY_PAGE_OFFSET + 0x09u,   /* KEY_20 */
};

CONST(uint8, CRYPTO_30_CRYWRAPPER_CONST) Crypto_30_CryWrapper_MappingTableSheToMapped[25] =
{
  /* Idx */ /* Mapped KeyId */ /* Name of Key */
  /* 0   */  0x18u,            /* SECRET_KEY */
  /* 1   */  0x15u,            /* MASTER_ECU_KEY */
  /* 2   */  0x16u,            /* BOOT_MAC_KEY */
  /* 3   */  0x17u,            /* BOOT_MAC */
  /* 4   */  0x01u,            /* KEY_1 */
  /* 5   */  0x02u,            /* KEY_2 */
  /* 6   */  0x03u,            /* KEY_3 */
  /* 7   */  0x04u,            /* KEY_4 */
  /* 8   */  0x05u,            /* KEY_5 */
  /* 9   */  0x06u,            /* KEY_6 */
  /* 10  */  0x07u,            /* KEY_7 */
  /* 11  */  0x08u,            /* KEY_8 */
  /* 12  */  0x09u,            /* KEY_9 */
  /* 13  */  0x0Au,            /* KEY_10 */
  /* 14  */  0x00u,            /* KEY_RAM */
  /* 15  */  0x0Bu,            /* KEY_11 */
  /* 16  */  0x0Cu,            /* KEY_12 */
  /* 17  */  0x0Du,            /* KEY_13 */
  /* 18  */  0x0Eu,            /* KEY_14 */
  /* 19  */  0x0Fu,            /* KEY_15 */
  /* 20  */  0x10u,            /* KEY_16 */
  /* 21  */  0x11u,            /* KEY_17 */
  /* 22  */  0x12u,            /* KEY_18 */
  /* 23  */  0x13u,            /* KEY_19 */
  /* 24  */  0x14u             /* KEY_20 */
};

#define CRYPTO_30_CRYWRAPPER_STOP_SEC_CONST_UNSPECIFIED
#include "MemMap.h" /* PRQA S 5087 */ /* MD_MSR_19.1 */

/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/

#define CRYPTO_30_CRYWRAPPER_START_SEC_CODE
#include "MemMap.h" /* PRQA S 5087 */ /* MD_MSR_19.1 */

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_KeyExtract()
 **********************************************************************************************************************/
/*! \brief         Call Cry Key Extract service.
 *  \details       -
 *  \param[in]     primCfgIdx           Index of the primitive config.
 *  \param[in]     dataPtr              Data pointer for the key extract service (e.g. plaintext or M1-M3).
 *  \param[in]     dataLength           Length of the provided data.
 *  \param[in]     keyPtr               Pointer to a key strucure (e.g. used to store M4-M5 after SHE key update).
 *  \param[out]    proofPtr             Pointer to the memory where the proof (M4-M5) can be stored.
 *                                      The availability of this parameter depends on the configuration.
 *  \param[in,out] proofLengthPtr       Contains the length of the available buffer and the length of the written proof after the function has returned.
 *                                      The availability of this parameter depends on the configuration.
 *  \return        E_OK                 Request successful.
 *                 E_NOT_OK             Request failed.
 *  \pre           -
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
CRYPTO_30_CRYWRAPPER_LOCAL FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_KeyExtract(
  uint32 primCfgIdx,
  P2CONST(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) dataPtr,
  uint32 dataLength,
  P2VAR(Csm_SymKeyType, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) keyPtr
#if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
  , P2VAR(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) proofPtr,
  P2VAR(uint32, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) proofLengthPtr
#endif
  );

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_TryObtainingKeyMLock()
 **********************************************************************************************************************/
/*! \brief         Try to get  the lock for the key management functions.
 *  \details       -
 *  \return        E_OK                 Request successful.
 *                 E_NOT_OK             Request failed.
 *  \pre           -
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
CRYPTO_30_CRYWRAPPER_LOCAL FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_TryObtainingKeyMLock(void);

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_FindPrimitiveCfgIdx()
 **********************************************************************************************************************/
/*! \brief         Find a matching primitive index in the configuration.
 *  \details       -
 *  \param[in]     usage                Type of the key extract function which should be searched.
 *  \param[in]     primCfgIdx           Index of the found primitive.
 *  \return        E_OK                 Request successful.
 *                 E_NOT_OK             Request failed.
 *  \pre           -
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
CRYPTO_30_CRYWRAPPER_LOCAL FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_FindPrimitiveCfgIdx(
  uint32 usage,
  P2VAR(uint32, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR)primCfgIdx);

/**********************************************************************************************************************
 *  LOCAL FUNCTIONS
 *********************************************************************************************************************/

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_TryObtainingKeyMLock()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 *
 *
 */
CRYPTO_30_CRYWRAPPER_LOCAL FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_TryObtainingKeyMLock(void)
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal = E_NOT_OK;

  /* ----- Implementation ------------------------------------------------- */
  /* #05 Lock driver object for the given job if it is not already locked. */
  SchM_Enter_Crypto_30_CryWrapper_CRYPTO_30_CRYWRAPPER_EXCLUSIVE_AREA_0();
  {
    /* #10 Check if lock of key management functions. */
    if (Crypto_30_CryWrapper_IsKeyMLockFree())
    {
      /* #15 Lock the key management functions. */
      Crypto_30_CryWrapper_SetKeyMLock();
      retVal = E_OK;
    }
  }
  SchM_Exit_Crypto_30_CryWrapper_CRYPTO_30_CRYWRAPPER_EXCLUSIVE_AREA_0();
  return retVal;
}

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_FindPrimitiveCfgIdx()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 *
 *
 */
CRYPTO_30_CRYWRAPPER_LOCAL FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_FindPrimitiveCfgIdx(uint32 usage, P2VAR(uint32, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) primCfgIdx)
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal = E_NOT_OK;
  uint32 primitiveCfgIdx;

  /* ----- Implementation ------------------------------------------------- */
  /* #10 Iterate over all key extract Cry configurations. */
  for (primitiveCfgIdx = 0; primitiveCfgIdx < Crypto_30_CryWrapper_GetSizeOfSymKeyExtractConfig(); primitiveCfgIdx++)
  {
    /* #15 Find a Cry configuration with the correct usage.  */
    if (Crypto_30_CryWrapper_GetCryptoSymKeyExtractUsageOfSymKeyExtractConfig(primitiveCfgIdx) == usage)
    {
      /* Store the found index in the passed pointer. */
      *primCfgIdx = primitiveCfgIdx; /* SBSW_CRYPTO_30_CRYWRAPPER_PARAMETER_PTR_ACCESS */
      retVal = E_OK;
    }
  }
  /* #20 Return if a matching configuration has been found. */
  return retVal;
}

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_KeyExtract()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */
CRYPTO_30_CRYWRAPPER_LOCAL FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_KeyExtract(
  uint32 primCfgIdx,
  P2CONST(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) dataPtr,
  uint32 dataLength,
  P2VAR(Csm_SymKeyType, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) keyPtr
#if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
  , P2VAR(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) proofPtr,
  P2VAR(uint32, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) proofLengthPtr
#endif
  )
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal;
  Csm_ReturnType cryRetVal;

  /* ----- Implementation ------------------------------------------------- */
  /* #10 Call Cry Key Extract start function. */
  cryRetVal = Crypto_30_CryWrapper_GetStartFuncOfSymKeyExtractConfig(primCfgIdx)( /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_EMPTY_CALL */
    Crypto_30_CryWrapper_GetInitPtrOfSymKeyExtractStartConfig(primCfgIdx));
  if (cryRetVal == CSM_E_OK)
  {
    /* #20 Call Cry Key Extract update function. */
    cryRetVal = Crypto_30_CryWrapper_GetUpdateFuncOfSymKeyExtractConfig(primCfgIdx)( /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_FUNCTION_PTR_FORWARDING */
      Crypto_30_CryWrapper_GetInitPtrOfSymKeyExtractUpdateConfig(primCfgIdx), dataPtr, dataLength);

    if (cryRetVal == CSM_E_OK)
    {
      /* #30 Call Cry Key Extract finish function. */
      cryRetVal = Crypto_30_CryWrapper_GetFinishFuncOfSymKeyExtractConfig(primCfgIdx)( /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_FUNCTION_PTR_FORWARDING */
        Crypto_30_CryWrapper_GetInitPtrOfSymKeyExtractFinishConfig(primCfgIdx),
        keyPtr
#if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
        , proofPtr,
        proofLengthPtr
#endif
        );
    }
  }

  /* #40 Check if service has completed without errors. */
  if (cryRetVal == CSM_E_OK)
  {
    retVal = E_OK;
  }
  /* #60 ELSE: indicate that an error occurred. */
  else
  {
#if (CRYPTO_30_CRYWRAPPER_CALL_FINISH_AFTER_ERROR == STD_ON)
    Csm_SymKeyType dummyKey = {0u};
# if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
    uint8 dummy = 0;
    uint32 dummylength = 0;
# endif
#endif

    /* #61 Check if CRY was busy. */
    if (cryRetVal == CSM_E_BUSY)
    {
      retVal = CRYPTO_E_BUSY;
    }
    else
    {
      retVal = E_NOT_OK;
    }

#if (CRYPTO_30_CRYWRAPPER_CALL_FINISH_AFTER_ERROR == STD_ON)
    /* #65 Call finish function of the service to reset the CRY state machine. */
    (void)Crypto_30_CryWrapper_GetFinishFuncOfSymKeyExtractConfig(primCfgIdx)( /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_FINISH_CALL */
      Crypto_30_CryWrapper_GetInitPtrOfSymKeyExtractFinishConfig(primCfgIdx),
      &dummyKey
# if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
      , &dummy,
      &dummylength
# endif
      );
#endif
  }

  /* #70 Return the result of the service call. */
  return retVal;
} /* PRQA S 6060 */ /* MD_MSR_STPAR */

/**********************************************************************************************************************
 *  GLOBAL FUNCTIONS
 *********************************************************************************************************************/

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_Hw_Init()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_Hw_Init(void)
{
  /* ----- Local Variables ---------------------------------------------- */
  Std_ReturnType retVal = E_OK;

  /* ----- Implementation ----------------------------------------------- */
  /* #10 Implement hardware specific initializations. */
#if Crypto_30_CryWrapper_IsRamKeyLifeCycleSupportOfWrapperGeneral()
  Crypto_30_CryWrapper_CurrentLifeCycle = 0u;
#endif

  /* #15 Free Key management function lock. */
  Crypto_30_CryWrapper_FreeKeyMLock();

  /* #20 Return if the initialization was successful or not. */
  return retVal;

} /* Crypto_30_CryWrapper_Hw_Init() */

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_Hw_KeyElementGet()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_Hw_KeyElementGet(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2VAR(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) resultPtr, /* PRQA S 3673 */ /* MD_CRYPTO_30_CRYWRAPPER_3673_2 */
  P2VAR(uint32, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) resultLengthPtr, /* PRQA S 3673 */ /* MD_CRYPTO_30_CRYWRAPPER_3673_2 */
  uint32 elementIndex)
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal;
#if (CRYPTO_30_CRYWRAPPER_SYMKEYWRAPSYMCONFIG == STD_ON)
  Csm_ReturnType cryRetVal;
#endif

#if Crypto_30_CryWrapper_IsRamKeyLifeCycleSupportOfWrapperGeneral()
  Csm_SymKeyType key;
  Csm_SymKeyType wrappingKey;

  /* Set length and Id as expected by the Cypress CRY driver */
  key.length = 2u;
  key.data[CRYPTO_30_CRYWRAPPER_OFFSET_KEYID] = CRYPTO_SHEKEYID_KEY_RAM; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */
  key.data[CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE] = Crypto_30_CryWrapper_CurrentLifeCycle; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */

  wrappingKey.length = 2u;
  wrappingKey.data[CRYPTO_30_CRYWRAPPER_OFFSET_KEYID] = CRYPTO_SHEKEYID_SECRET_KEY; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */
  wrappingKey.data[CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE] = 0u; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */
#else
  Csm_SymKeyType key = { 0u, { 0u } };
  Csm_SymKeyType wrappingKey = { 0u, { 0u } };
#endif

  /* ----- Implementation ----------------------------------------------- */
  /* #10 Try to obtain lock for key management functions. */
  if (Crypto_30_CryWrapper_TryObtainingKeyMLock() == E_NOT_OK)
  {
    retVal = CRYPTO_E_BUSY;
  }
  else
  {
    /* #20 Check if RAM key shall be exported as (M1|M2|M3) or (M1|M2|M3|M4|M5). */
    if ( ( (*resultLengthPtr == 64u) || (*resultLengthPtr == 112u) )
      && (CRYPTO_30_CRYWRAPPER_RA_ENCRYPTED == Crypto_30_CryWrapper_GetReadOfKeyElementInfo(
        Crypto_30_CryWrapper_GetKeyElementInfoIdxOfKeyElements(elementIndex) ) ) )
    {
      /* #25 Call Cry KeyWrapSym interface to export the RAM key. */
#if (CRYPTO_30_CRYWRAPPER_SYMKEYWRAPSYMCONFIG == STD_ON)
      cryRetVal = Crypto_30_CryWrapper_GetStartFuncOfSymKeyWrapSymConfig(0)(Crypto_30_CryWrapper_GetInitPtrOfSymKeyWrapSymStartConfig(0), &key, &wrappingKey); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_STACK_VARIABLE_AS_PTR */

      if (cryRetVal == CSM_E_OK)
      {
        cryRetVal = Crypto_30_CryWrapper_GetUpdateFuncOfSymKeyWrapSymConfig(0)(Crypto_30_CryWrapper_GetInitPtrOfSymKeyWrapSymUpdateConfig(0), resultPtr, resultLengthPtr); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_FUNCTION_PTR_FORWARDING */

        if (cryRetVal == CSM_E_OK)
        {
          cryRetVal = Crypto_30_CryWrapper_GetFinishFuncOfSymKeyWrapSymConfig(0)(Crypto_30_CryWrapper_GetInitPtrOfSymKeyWrapSymFinishConfig(0)); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_EMPTY_CALL */
        }
      }

      /* #30 Check if service has completed without errors. */
      if (cryRetVal == CSM_E_OK)
      {
        retVal = E_OK;
      }
      /* #32 ELSE: indicate that an error occurred. */
      else
      {
        /* #33 Check if CRY was busy. */
        if (cryRetVal == CSM_E_BUSY)
        {
          retVal = CRYPTO_E_BUSY;
        }
        else
        {
          retVal = E_NOT_OK;
        }

# if (CRYPTO_30_CRYWRAPPER_CALL_FINISH_AFTER_ERROR == STD_ON)
        /* #34 Call finish function of the service to reset the CRY state machine. */
        (void)Crypto_30_CryWrapper_GetFinishFuncOfSymKeyWrapSymConfig(0)(Crypto_30_CryWrapper_GetInitPtrOfSymKeyWrapSymFinishConfig(0)); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_FINISH_CALL */
# endif
      }
#else
      CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(resultPtr); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */
      CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(key); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */
      CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(wrappingKey); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */

      retVal = E_NOT_OK;
#endif
    }
    else
    {
      retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
    }
    /* #50 Free the key management functions lock. */
    Crypto_30_CryWrapper_FreeKeyMLock();
  }

  CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(cryptoKeyId); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */
  CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(keyElementId); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */

  /* #60 Return the result of the service call. */
  return retVal;
} /* PRQA S 6080 */ /* MD_MSR_STMIF */

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_Hw_KeyElementSet()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_Hw_KeyElementSet(uint32 cryptoKeyId,
  uint32 keyElementId,
  P2CONST(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) keyPtr,
  uint32 keyLength,
  uint32 elementIndex)
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal;
  Csm_SymKeyType key = { 0u, { 0u } };
  uint32 primCfgIdx;
#if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
  uint8 proof[48] = {0u};
  uint32 proofLength = 48u;
#endif

#if (Crypto_30_CryWrapper_GetKeyUpdateSchemeOfWrapperGeneral() == CRYPTO_30_CRYWRAPPER_KEYID_M1_M2_M3)
  uint8 updateMsg[CRYPTO_30_CRYWRAPPER_SHE_KEY_UPDATE_LENGTH_WITH_KEYID] = { 0u };
  uint8_least updateMsgIdx;
#endif

  /* ----- Implementation ----------------------------------------------- */
  /* #04 Check if element may be processed in hardware. */
  if ( (keyElementId != 1u)
    || (cryptoKeyId > CRYPTO_30_CRYWRAPPER_MAX_SHEKEYID) )
  {
    /* #05 Indicate that key has not been processed with hardware. */
    retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
  }
  /* #10 Try to obtain lock for key management functions. */
  else if (Crypto_30_CryWrapper_TryObtainingKeyMLock() == E_NOT_OK)
  {
    retVal = CRYPTO_E_BUSY;
  }
  else
  {
    /* #20 Check if Key shall be updated using SHE key update protocol (M1|M2|M3). */
    if (keyLength == CRYPTO_30_CRYWRAPPER_SHE_KEY_UPDATE_LENGTH)
    {
      /* #25 Check if write access flags are valid. */
      if ( (CRYPTO_30_CRYWRAPPER_WA_ENCRYPTED == (Crypto_30_CryWrapper_GetWriteOfKeyElementInfo(Crypto_30_CryWrapper_GetKeyElementInfoIdxOfKeyElements(elementIndex) ) ) )
        || (CRYPTO_30_CRYWRAPPER_WA_ALLOWED == (Crypto_30_CryWrapper_GetWriteOfKeyElementInfo(Crypto_30_CryWrapper_GetKeyElementInfoIdxOfKeyElements(elementIndex) ) ) ) )
      {
        boolean keyUpdatePerformed = FALSE;
#if (Crypto_30_CryWrapper_GetKeyUpdateSchemeOfWrapperGeneral() == CRYPTO_30_CRYWRAPPER_KEYID_M1_M2_M3)
        /* #30 If Cry expects a KeyId in front of the M1-M3, prepare the update message. */
# if (Crypto_30_CryWrapper_GetKeyIdMappingOfWrapperGeneral() == CRYPTO_30_CRYWRAPPER_KEYIDTYPE_RAW)
        updateMsg[0u] = (uint8)cryptoKeyId; /* SBSW_CRYPTO_30_CRYWRAPPER_STACK_ARRAY_ACCESS_WITH_SIZE */
# else
        updateMsg[0u] = (uint8)Crypto_30_CryWrapper_MappingTableSheToMapped[cryptoKeyId]; /* SBSW_CRYPTO_30_CRYWRAPPER_STACK_ARRAY_ACCESS_WITH_SIZE */
# endif
        for (updateMsgIdx = 0u; updateMsgIdx < CRYPTO_30_CRYWRAPPER_SHE_KEY_UPDATE_LENGTH; updateMsgIdx++)
        {
          updateMsg[updateMsgIdx + 1u] = keyPtr[updateMsgIdx]; /* SBSW_CRYPTO_30_CRYWRAPPER_STACK_ARRAY_ACCESS_WITH_SIZE */
        }

        if (Crypto_30_CryWrapper_FindPrimitiveCfgIdx(CRYPTO_30_CRYWRAPPER_ALL_KEYS, &primCfgIdx) == E_OK) /* COV_CRYPTO_30_CRYWRAPPER_FIND_PRIMITIVE */ /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_STACK_VARIABLE_AS_PTR */
        {
          /* #35 Send the (KeyId|M1|M2|M3) to the Cry if a matching configuration has been found. */
          if (Crypto_30_CryWrapper_KeyExtract(primCfgIdx,
            updateMsg,
            CRYPTO_30_CRYWRAPPER_SHE_KEY_UPDATE_LENGTH_WITH_KEYID,
            &key
# if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
            , proof,
            &proofLength
# endif
            ) == E_OK) /* SBSW_CRYPTO_30_CRYWRAPPER_FORWARDING_PTR_AND_STACK_VARIABLE */
          {
            keyUpdatePerformed = TRUE;
          }
        }
#else /* CRYPTO_30_CRYWRAPPER_MULTIPLE_CONFIGS */
        /* #40 If Cry uses different configurations for different key pages, find a matching configuration. */
        uint32 usage;

        if (Crypto_30_CryWrapper_MappingTableSheToMapped[cryptoKeyId] == CRYPTO_30_CRYWRAPPER_KEYID_MAPPED_KEY_RAM)
        {
          usage = CRYPTO_30_CRYWRAPPER_RAMKEY;
        }
        else if ( (Crypto_30_CryWrapper_MappingTableSheToMapped[cryptoKeyId] < CRYPTO_30_CRYWRAPPER_KEYID_MAPPED_KEY_11)
               || (Crypto_30_CryWrapper_MappingTableSheToMapped[cryptoKeyId] > CRYPTO_30_CRYWRAPPER_KEYID_MAPPED_KEY_20) )
        {
          usage = CRYPTO_30_CRYWRAPPER_PAGE_0;
        }
        else
        {
          usage = CRYPTO_30_CRYWRAPPER_PAGE_1;
        }

        if (Crypto_30_CryWrapper_FindPrimitiveCfgIdx(usage, &primCfgIdx) == E_OK) /* COV_CRYPTO_30_CRYWRAPPER_FIND_PRIMITIVE */ /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_STACK_VARIABLE_AS_PTR */
        {
          /* #45 Send the (M1|M2|M3) to the Cry if a matching configuration has been found. */
          if (Crypto_30_CryWrapper_KeyExtract(primCfgIdx,
            keyPtr,
            keyLength,
            &key
# if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
            , proof,
            &proofLength
# endif
            ) == CSM_E_OK) /* SBSW_CRYPTO_30_CRYWRAPPER_FORWARDING_PTR_AND_STACK_VARIABLE */
          {
            keyUpdatePerformed = TRUE;
          }
        }
#endif
        /* #50 If key update was successful: */
        if (keyUpdatePerformed == TRUE)
        {
          /* #55 Set written length to 16. */
          Crypto_30_CryWrapper_SetKeyElementWrittenLength(elementIndex, 16u);

          /* #56 Free the key management functions lock. */
          Crypto_30_CryWrapper_FreeKeyMLock();

#if Crypto_30_CryWrapper_IsRamKeyLifeCycleSupportOfWrapperGeneral()
          if (Crypto_30_CryWrapper_MappingTableSheToMapped[cryptoKeyId] == CRYPTO_30_CRYWRAPPER_KEYID_MAPPED_KEY_RAM)
          {
            Crypto_30_CryWrapper_CurrentLifeCycle = key.data[CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE]; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */
          }
#endif
          /* #57 Store the proof in key elements. */
          retVal = Crypto_30_CryWrapper_StoreProof(
            cryptoKeyId,
#if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
            proof,
            proofLength
#else
            key.data,
            key.length
#endif
          ); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_STACK_VARIABLE_AS_PTR */
        }
        else
        {
          retVal = E_NOT_OK;
        }
      }
      else
      {
        retVal = CRYPTO_E_KEY_WRITE_FAIL;
      }
    }

    /* #70 Check if plain text key shall be stored. */
    else if (keyLength == 16u)
    {
      /* #71 Check if write access flags are valid. */
      if (CRYPTO_30_CRYWRAPPER_WA_ALLOWED == (Crypto_30_CryWrapper_GetWriteOfKeyElementInfo(Crypto_30_CryWrapper_GetKeyElementInfoIdxOfKeyElements(elementIndex))))
      {
        /* #75 Find a matching Cry configuration. */
#if (Crypto_30_CryWrapper_GetKeyUpdateSchemeOfWrapperGeneral() == CRYPTO_30_CRYWRAPPER_KEYID_M1_M2_M3)
        if (Crypto_30_CryWrapper_FindPrimitiveCfgIdx(CRYPTO_30_CRYWRAPPER_ALL_KEYS, &primCfgIdx) == E_OK) /* COV_CRYPTO_30_CRYWRAPPER_FIND_PRIMITIVE */ /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_STACK_VARIABLE_AS_PTR */
#else /* CRYPTO_30_CRYWRAPPER_MULTIPLE_CONFIGS */
        if (Crypto_30_CryWrapper_FindPrimitiveCfgIdx(CRYPTO_30_CRYWRAPPER_PLAINKEY, &primCfgIdx) == E_OK) /* COV_CRYPTO_30_CRYWRAPPER_FIND_PRIMITIVE */ /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_STACK_VARIABLE_AS_PTR */
#endif
        {
          /* #76 Call Cry Key Extract to store the plaintext key to the SHE. */
          retVal = Crypto_30_CryWrapper_KeyExtract(
            primCfgIdx,
            keyPtr,
            keyLength,
            &key
#if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
            , proof,
            &proofLength
#endif
          ); /* SBSW_CRYPTO_30_CRYWRAPPER_FORWARDING_PTR_AND_STACK_VARIABLE */
#if Crypto_30_CryWrapper_IsRamKeyLifeCycleSupportOfWrapperGeneral()
          Crypto_30_CryWrapper_CurrentLifeCycle = key.data[CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE]; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */
#endif
        }
        else
        {
          retVal = E_NOT_OK;
        }
      }
      else
      {
        retVal = CRYPTO_E_KEY_WRITE_FAIL;
      }
    }
    /* #100 If key has not been processed. */
    else
    {
      /* #105 Indicate that key has not been processed with hardware. */
      retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
    }
    /* #110 Free the key management functions lock. */
    Crypto_30_CryWrapper_FreeKeyMLock();
  }

  return retVal;
} /* PRQA S 6030,6080 */ /* MD_MSR_STCYC */ /* MD_MSR_STMIF */


/**********************************************************************************************************************
 * Crypto_30_CryWrapper_Hw_RandomSeed()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_Hw_RandomSeed(
  uint32 cryptoKeyId,
  P2CONST(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) entropyPtr,
  uint32 entropyLength)
{
#if (CRYPTO_30_CRYWRAPPER_RANDOMSEEDCONFIG == STD_ON)
  Csm_ReturnType cryRetVal;
  Std_ReturnType retVal;
#else
  Std_ReturnType retVal = E_NOT_OK;
#endif

#if (CRYPTO_30_CRYWRAPPER_RANDOMSEEDCONFIG == STD_ON)
  /* #10 Call Cry seed service start. */
  cryRetVal = Crypto_30_CryWrapper_GetStartFuncOfRandomSeedConfig(0)(Crypto_30_CryWrapper_GetInitPtrOfRandomSeedStartConfig(0)); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_EMPTY_CALL */

  if (cryRetVal == CSM_E_OK)
  {
    /* #20 Call Cry seed service update. */
    cryRetVal = Crypto_30_CryWrapper_GetUpdateFuncOfRandomSeedConfig(0)(Crypto_30_CryWrapper_GetInitPtrOfRandomSeedUpdateConfig(0), entropyPtr, entropyLength); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_FUNCTION_PTR_FORWARDING */
    if (cryRetVal == CSM_E_OK)
    {
      /* #30 Call Cry seed service finish. */
      cryRetVal = Crypto_30_CryWrapper_GetFinishFuncOfRandomSeedConfig(0)(Crypto_30_CryWrapper_GetInitPtrOfRandomSeedFinishConfig(0)); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_EMPTY_CALL */
    }
  }

  /* #40 Check if service has completed without errors. */
  if (cryRetVal == CSM_E_OK)
  {
    retVal = E_OK;
  }
  /* #50 Check if CRY was busy. */
  else if (cryRetVal == CSM_E_BUSY)
  {
    retVal = CRYPTO_E_BUSY;
  }
  /* #60 ELSE: indicate that an error occurred. */
  else
  {
    retVal = E_NOT_OK;
# if (CRYPTO_30_CRYWRAPPER_CALL_FINISH_AFTER_ERROR == STD_ON)
    /* #65 Call finish function of the service to reset the CRY state machine. */
    (void)Crypto_30_CryWrapper_GetFinishFuncOfRandomSeedConfig(0)(Crypto_30_CryWrapper_GetInitPtrOfRandomSeedFinishConfig(0)); /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_FINISH_CALL */
# endif
  }
#else
  CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(entropyPtr); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */
  CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(entropyLength); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */
#endif

  CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(cryptoKeyId); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */

  /* #70 Return the result of the service call. */
  return retVal;
}

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_Hw_KeyGenerate()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_Hw_KeyGenerate(
  uint32 cryptoKeyId)
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal = E_NOT_OK;

  /* ----- Implementation ------------------------------------------------- */
  /* #10 The function is empty. Do nothing. */

  CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(cryptoKeyId); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */

  return retVal;
}

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_Hw_KeyExchangeCalcPubVal()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_Hw_KeyExchangeCalcPubVal(
  uint32 cryptoKeyId,
  P2VAR(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) publicValuePtr, /* PRQA S 3673 */ /* MD_CRYPTO_30_CRYWRAPPER_3673_2 */
  P2VAR(uint32, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) publicValueLengthPtr) /* PRQA S 3673 */ /* MD_CRYPTO_30_CRYWRAPPER_3673_2 */
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal = E_NOT_OK;
  uint8 privKey[SECLIB_ECC_PRIVKEY_LEN];
  uint8 pubKey[SECLIB_ECC_PUBKEY_LEN];
  Crypto_30_CryWrapper_KeyElementsIterType elementIdx;

  /* ----- Implementation ------------------------------------------------- */
  /* #10 ECC public key generation via SecurityLib ECC extension (P-224).
   *     The ephemeral private scalar is generated inside SecLib and stored
   *     in the PRIVKEY element so the later Csm_KeyExchangeCalcSecret call
   *     can use it (third-party workflow, vKeyM_MPKA TR 5.5; MPKA itself
   *     only zeroizes this element after the negotiation). */
  memset(privKey, 0, sizeof(privKey));
  memset(pubKey, 0, sizeof(pubKey));

  if (!SecLib_EccIsInitialized())
  {
    /* Fail closed: ECC backend not initialized. */
    retVal = E_NOT_OK;
  }
  else if (*publicValueLengthPtr < SECLIB_ECC_PUBKEY_LEN)
  {
    retVal = E_NOT_OK;
  }
  else if (SecLib_EccGenerateEphemeralKey(privKey, pubKey) != OPERATION_SUCCESSFUL)
  {
    retVal = E_NOT_OK;
  }
  else if (Crypto_30_CryWrapper_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY, &elementIdx) != E_OK)
  {
    retVal = E_NOT_OK;
  }
  else
  {
    /* Store the ephemeral private scalar (28 bytes, P-224). */
    Crypto_30_CryWrapper_KeyElementSetInternal(elementIdx, privKey, SECLIB_ECC_PRIVKEY_LEN);

    /* Provide the public point as uncompressed X||Y (56 bytes). */
    memcpy(publicValuePtr, pubKey, SECLIB_ECC_PUBKEY_LEN);
    *publicValueLengthPtr = SECLIB_ECC_PUBKEY_LEN;

    retVal = E_OK;
  }

  /* Erase local secret material on every exit path. */
  memset(privKey, 0, sizeof(privKey));
  memset(pubKey, 0, sizeof(pubKey));

  CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(cryptoKeyId);  /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */

  return retVal;
}

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_Hw_KeyExchangeCalcSecret()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_Hw_KeyExchangeCalcSecret(
  uint32 cryptoKeyId,
  P2CONST(uint8, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) partnerPublicValuePtr,
  uint32 partnerPublicValueLength)
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal = E_NOT_OK;
  uint8 privKey[SECLIB_ECC_PRIVKEY_LEN];
  uint8 sharedSecret[SECLIB_ECC_PUBKEY_LEN];
  uint32 privKeyLen = sizeof(privKey);
  uint32 sharedValueLen;
  Crypto_30_CryWrapper_KeyElementsIterType elementIdx;

  /* ----- Implementation ------------------------------------------------- */
  /* #10 ECDH shared secret via SecurityLib ECC extension (P-224).
   *     Reads the ephemeral private scalar from PRIVKEY (set by the
   *     preceding CalcPubVal call), computes K = d * Q_partner with
   *     on-curve validation of the peer point, and stores X||Y in the
   *     SHAREDVALUE element (element ID 1). The configured length of
   *     SHAREDVALUE selects the encoding: 28 = x only, 56 = x||y
   *     (vKeyM_MPKA TR 5.6, CS.00172 REQ 5.7.2 / 5.7.5). */
  memset(privKey, 0, sizeof(privKey));
  memset(sharedSecret, 0, sizeof(sharedSecret));

  if (!SecLib_EccIsInitialized())
  {
    retVal = E_NOT_OK;
  }
  else if (partnerPublicValueLength != SECLIB_ECC_PUBKEY_LEN)
  {
    retVal = E_NOT_OK;
  }
  else if (Crypto_30_CryWrapper_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY, &elementIdx) != E_OK)
  {
    retVal = E_NOT_OK;
  }
  else if (Crypto_30_CryWrapper_Local_KeyElementGet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY, privKey, &privKeyLen) != E_OK)
  {
    retVal = E_NOT_OK;
  }
  else if (privKeyLen != SECLIB_ECC_PRIVKEY_LEN)
  {
    retVal = E_NOT_OK;
  }
  else if (SecLib_EccComputeSharedSecret(privKey, partnerPublicValuePtr, sharedSecret) != OPERATION_SUCCESSFUL)
  {
    retVal = E_NOT_OK;
  }
  else if (Crypto_30_CryWrapper_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE, &elementIdx) != E_OK)
  {
    retVal = E_NOT_OK;
  }
  else
  {
    sharedValueLen = Crypto_30_CryWrapper_GetKeyElementLength(elementIdx);

    if (sharedValueLen == SECLIB_ECC_COORD_LEN)
    {
      /* x-coordinate only (e.g. CAK derivation, CS.00172 REQ 5.7.5). */
      Crypto_30_CryWrapper_KeyElementSetInternal(elementIdx, sharedSecret, SECLIB_ECC_COORD_LEN);
      retVal = E_OK;
    }
    else if (sharedValueLen == SECLIB_ECC_PUBKEY_LEN)
    {
      /* x- and y-coordinate (Group Message key, CS.00172 REQ 5.7.2). */
      Crypto_30_CryWrapper_KeyElementSetInternal(elementIdx, sharedSecret, SECLIB_ECC_PUBKEY_LEN);
      retVal = E_OK;
    }
    else
    {
      retVal = E_NOT_OK;
    }
  }

  /* Erase local secret material on every exit path. */
  memset(privKey, 0, sizeof(privKey));
  memset(sharedSecret, 0, sizeof(sharedSecret));

  return retVal;
}

/**********************************************************************************************************************
 * Crypto_30_CryWrapper_Hw_KeyDerive()
 **********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_Hw_KeyDerive(
  uint32 cryptoKeyId,
  uint32 targetCryptoKeyId)
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal = E_NOT_OK;
  uint8 password[SECLIB_ECC_PUBKEY_LEN];
  uint8 salt[2u]; /* 1-byte msgGrpId (SecOC) or 2-byte prefix+ID (MacSec) */
  uint8 derived[SECLIB_ECC_KDF_OUT_MAX];
  uint32 passwordLen = sizeof(password);
  uint32 saltLen = sizeof(salt);
  uint32 targetLen;
  Crypto_30_CryWrapper_KeyElementsIterType targetIdx;

  /* ----- Implementation ------------------------------------------------- */
  /* #10 ANSI X9.63 KDF with SHA-256 via SecurityLib ECC extension.
   *     PASSWORD (element 1 of the KDF input key) = shared value,
   *     SALT (element 13 of the KDF input key) = 1-byte message group ID
   *     (vKeyM_MPKA CryptoStateMachine; CS.00172 REQ 5.7.2). The output is
   *     written to element 1 of the target key with the target element's
   *     configured length. */
  memset(password, 0, sizeof(password));
  memset(salt, 0, sizeof(salt));
  memset(derived, 0, sizeof(derived));

  if (!SecLib_EccIsInitialized())
  {
    retVal = E_NOT_OK;
  }
  else if (Crypto_30_CryWrapper_Local_KeyElementGet(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, password, &passwordLen) != E_OK)
  {
    retVal = E_NOT_OK;
  }
  else if (Crypto_30_CryWrapper_Local_KeyElementGet(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_SALT, salt, &saltLen) != E_OK)
  {
    retVal = E_NOT_OK;
  }
  else if (Crypto_30_CryWrapper_Local_KeyElementSearch(targetCryptoKeyId, 1u, &targetIdx) != E_OK)
  {
    retVal = E_NOT_OK;
  }
  else
  {
    targetLen = Crypto_30_CryWrapper_GetKeyElementLength(targetIdx);

    if ((targetLen == 0u) || (targetLen > SECLIB_ECC_KDF_OUT_MAX))
    {
      retVal = E_NOT_OK;
    }
    else if (SecLib_EccKdfX963Sha256(password, passwordLen, salt, saltLen, derived, targetLen) != OPERATION_SUCCESSFUL)
    {
      retVal = E_NOT_OK;
    }
    else
    {
      Crypto_30_CryWrapper_KeyElementSetInternal(targetIdx, derived, targetLen);
      retVal = E_OK;
    }
  }

  /* Erase local secret material on every exit path. */
  memset(password, 0, sizeof(password));
  memset(derived, 0, sizeof(derived));

  return retVal;
}

#if (Crypto_30_CryWrapper_IsProvideCsmNotificationApiOfWrapperGeneral() == TRUE)
/**********************************************************************************************************************
 *  Csm_MacVerifyCallbackNotification()
 *********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 */
FUNC(void, CRYPTO_30_CRYWRAPPER_CODE) Csm_MacVerifyCallbackNotification(VAR(Csm_ReturnType, AUTOMATIC) Result) /* COV_CRYPTO_30_CRYWRAPPER_NOT_USED_CSM_CALLOUTS */
{
  /* Callouts are needed for CRYs which require the callout, despite beeing configured as synchronous (e.g. postbuild loadable Crys) */
  /* ----- Implementation ------------------------------------------------- */
  /* #10 The function is empty. Do nothing. */
  CRYPTO_30_CRYWRAPPER_DUMMY_STATEMENT(Result); /* PRQA S 3112 */ /* MD_MSR_14.2 */ /*lint !e438 */
}

/**********************************************************************************************************************
 *  Csm_MacVerifyServiceFinishNotification()
 *********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 */
FUNC(void, CRYPTO_30_CRYWRAPPER_CODE) Csm_MacVerifyServiceFinishNotification(void) /* COV_CRYPTO_30_CRYWRAPPER_NOT_USED_CSM_CALLOUTS */
{
  /* Callouts are needed for CRYs which require the callout, despite beeing configured as synchonous (e.g. postbuild loadable Crys) */
  /* ----- Implementation ------------------------------------------------- */
  /* #10 The function is empty. Do nothing. */
}
#endif /* (Crypto_30_CryWrapper_IsProvideCsmNotificationApiOfWrapperGeneral() == TRUE) */

/**********************************************************************************************************************
 *  Crypto_30_CryWrapper_GetSymKey()
 *********************************************************************************************************************/
/*!
 *
 * Internal comment removed.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */
FUNC(Std_ReturnType, CRYPTO_30_CRYWRAPPER_CODE) Crypto_30_CryWrapper_GetSymKey(
  uint32 cryptoKeyId,
  P2VAR(Csm_SymKeyType, AUTOMATIC, CRYPTO_30_CRYWRAPPER_APPL_VAR) key)
{
  /* ----- Local Variables ------------------------------------------------ */
  Std_ReturnType retVal;
#if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
  uint8 proof[48];
  uint32 proofLength = 48u;
#endif

  /* ----- Implementation ------------------------------------------------- */
  /* #10 If key is already present in the SHE: */
  if (cryptoKeyId <= CRYPTO_30_CRYWRAPPER_MAX_SHEKEYID)
  {
    uint32 keyId;

    retVal = E_OK;

    /* #15 Convert keyId if needed. */
#if (Crypto_30_CryWrapper_GetKeyIdMappingOfWrapperGeneral() == CRYPTO_30_CRYWRAPPER_KEYIDTYPE_RAW)
    keyId = Crypto_30_CryWrapper_MappingTableSheToCryShe[cryptoKeyId];
#else
    keyId = Crypto_30_CryWrapper_MappingTableSheToMapped[cryptoKeyId];
#endif
    /* #16 Store keyId to the key structure. */
#if Crypto_30_CryWrapper_IsRamKeyLifeCycleSupportOfWrapperGeneral()
    key->length = 2u; /* SBSW_CRYPTO_30_CRYWRAPPER_KEY_PTR_ACCESS */

    /* Set the Life Cycle to the current value if it is a RAM-Key */
    if (Crypto_30_CryWrapper_MappingTableSheToMapped[cryptoKeyId] == CRYPTO_30_CRYWRAPPER_KEYID_MAPPED_KEY_RAM)
    {
      key->data[CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE] = Crypto_30_CryWrapper_CurrentLifeCycle; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */
    }
    else
    {
      key->data[CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE] = 0u; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */
    }
#else
    key->length = 1u; /* SBSW_CRYPTO_30_CRYWRAPPER_KEY_PTR_ACCESS */
#endif
    key->data[0u] = (Csm_AlignType)keyId; /* SBSW_CRYPTO_30_CRYWRAPPER_KEY_PTR_ACCESS */
  }
  /* #20 Else if the key is located in the key storage of the crypto driver: */
  else
  {
#if (CRYPTO_30_CRYWRAPPER_USE_KEY_EXTRACT_FOR_PLAINTEXT_KEY == STD_ON)
    uint32 primCfgIdx;
    Csm_SymKeyType tmpKey;
#endif

    /* #25 Get plain text key from key storage. */
    key->length =  CRYPTO_CRYWRAPPER_DIV8(CSM_MAX_ALIGN_SCALAR_TYPE * CSM_SYM_KEY_MAX_SIZE); /* SBSW_CRYPTO_30_CRYWRAPPER_KEY_PTR_ACCESS */
    retVal = Crypto_30_CryWrapper_Local_KeyElementGet(cryptoKeyId, 1u, key->data, &key->length); /* SBSW_CRYPTO_30_CRYWRAPPER_STACK_VARIABLE_AS_PTR */

    /* #30 If key extract shall be used to update plaintext key: */
#if (CRYPTO_30_CRYWRAPPER_USE_KEY_EXTRACT_FOR_PLAINTEXT_KEY == STD_ON)
    if (retVal == E_OK)
    {
      retVal = E_NOT_OK;

      /* #35 Find matching Cry configuration for Key Extract. */
# if (Crypto_30_CryWrapper_GetKeyUpdateSchemeOfWrapperGeneral() == CRYPTO_30_CRYWRAPPER_MULTIPLE_CONFIGS)
      if (Crypto_30_CryWrapper_FindPrimitiveCfgIdx(CRYPTO_30_CRYWRAPPER_RAMKEY, &primCfgIdx) == E_OK) /* COV_CRYPTO_30_CRYWRAPPER_FIND_PRIMITIVE */ /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_STACK_VARIABLE_AS_PTR */
# else
      if (Crypto_30_CryWrapper_FindPrimitiveCfgIdx(CRYPTO_30_CRYWRAPPER_ALL_KEYS, &primCfgIdx) == E_OK) /* COV_CRYPTO_30_CRYWRAPPER_FIND_PRIMITIVE */ /* SBSW_CRYPTO_30_CRYWRAPPER_CRY_STACK_VARIABLE_AS_PTR */
# endif
      {
        if (Crypto_30_CryWrapper_KeyExtract(
          primCfgIdx,
          key->data,
          16u,
          &tmpKey
# if (CRYPTO_30_CRYWRAPPER_PROOF_BUFFER_POINTER_SUPPORT == STD_ON)
          , proof,
          &proofLength
# endif
        ) == E_OK) /* SBSW_CRYPTO_30_CRYWRAPPER_FORWARDING_PTR_AND_STACK_VARIABLE */
        {
# if Crypto_30_CryWrapper_IsRamKeyLifeCycleSupportOfWrapperGeneral()
          /* Store the new life cycle */
          Crypto_30_CryWrapper_CurrentLifeCycle = tmpKey.data[CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE]; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */

          key->data[CRYPTO_30_CRYWRAPPER_OFFSET_LIFECYCLE] = Crypto_30_CryWrapper_CurrentLifeCycle; /* SBSW_CRYPTO_30_CRYWRAPPER_ARRAY_ACCESS_WITH_COMPILE_TIME_SIZE_CHECK */
          key->length = 2u; /* SBSW_CRYPTO_30_CRYWRAPPER_FORWARDING_PTR_AND_STACK_VARIABLE */
# else
          key->length = 1u; /* SBSW_CRYPTO_30_CRYWRAPPER_FORWARDING_PTR_AND_STACK_VARIABLE */
# endif
          /* #40 Set keyId to RAM key and length to 1. */
# if (Crypto_30_CryWrapper_GetKeyIdMappingOfWrapperGeneral() == CRYPTO_30_CRYWRAPPER_KEYIDTYPE_MAPPED)
          key->data[CRYPTO_30_CRYWRAPPER_OFFSET_KEYID] = CRYPTO_30_CRYWRAPPER_KEYID_MAPPED_KEY_RAM; /* SBSW_CRYPTO_30_CRYWRAPPER_KEY_PTR_ACCESS */
# else
          key->data[CRYPTO_30_CRYWRAPPER_OFFSET_KEYID] = CRYPTO_SHEKEYID_KEY_RAM; /* SBSW_CRYPTO_30_CRYWRAPPER_KEY_PTR_ACCESS */
# endif

          retVal = E_OK;
        }
      }
    }
#endif
  }

  return retVal;
}

#define CRYPTO_30_CRYWRAPPER_STOP_SEC_CODE
#include "MemMap.h" /* PRQA S 5087 */ /* MD_MSR_19.1 */

/**********************************************************************************************************************
 *  END OF FILE: Crypto_30_CryWrapper_Hw.c
 *********************************************************************************************************************/
