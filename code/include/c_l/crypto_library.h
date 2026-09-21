/* ===========================================================================**
**                                                     **
** ===========================================================================**
**                      +++++++++++++++++++++++++++++                         **
**   Modulo:            +   SecurityLib.h           +                         **
**                      +++++++++++++++++++++++++++++                         **
**                                                                            **
**   Progetto:          TBM2                                                  **
** ===========================================================================*/
/*******************************************************************************
* File Name    : SecurityLib.h
* Version      : RH850/F1K
* Tool-Chain   : GHS
* Description  : This file implements all Security library features
*******************************************************************************/
/*
|-----------------------------------------------------------------------------
|               A U T H O R   I D E N T I T Y
|-----------------------------------------------------------------------------
| Initials     Name                      Company
| --------     ---------------------     -------------------------------------
| AC           Andrea Cericola           Pimsoft Spa
|-----------------------------------------------------------------------------
|               R E V I S I O N   H I S T O R Y
|-----------------------------------------------------------------------------
| Date        Ver  Author   Description
| ---------   ---  ------   --------------------------------------------------
| 03/04/2018  0.1    AC     First draft
| 23/05/2018  0.2    AC     Add key management
| 15/06/2018  0.3    AC     KeySHEUpdate completed and debugged
|
*/
#ifndef SECURITYLIB_H
#define SECURITYLIB_H

/*****************************************************************************/
/**                            INCLUDE
******************************************************************************/
#include "crypto_library_type.h"
#include "Crypto_30_CryWrapper_GeneratedTypes.h"
#include "Crc.h"
#include "cfgs.h"
/*****************************************************************************/
/**                            DEFINE
******************************************************************************/
#define STATUS_ICUS_ENABLED ((CRY_30_RH850ICUS_ICUSTS & CRY_30_RH850ICUS_ICUSTS_ICUEN) == CRY_30_RH850ICUS_ICU_ENABLED)
#define ICUS_ERROR (CRY_30_RH850ICUS_ERR & CRY_30_RH850ICUS_ERR_ERR_MASK)

#define BLOCK_SIZE 64u

#define NVM_CMAC_APP_BLOCK_SIZE 96u
#define NVM_CMAC_BLF_BLOCK_SIZE 92u
#define NVM_JTAG_BLOCK_SIZE 104u
#define NVM_SAM_BLOCK_SIZE 64u
#define NVM_CERTSTORE_BLOCK_SIZE 64u
#define NVM_DATASET_BLOCK_SIZE 111u

/******************************************************************************/
/**                        PROTOTYPE FUNCTION
*******************************************************************************/

/* Initialize the Crypto Unit and activate the library functions
 * @return TRUE on success, FALSE for error */
boolean SecLib_Init(void);

/* Check if ICUS Crypto unit is enabled
 * @return TRUE if ICUS is enabled, otherwise FALSE */
boolean SecLib_CheckStatusICUS(void);

/* returns the secure boot status */
boolean SecLib_SecureBootEnabled(void);

/* Generation of random numbers
 * @param  pNumber: pointer to the memory location which will hold the random number
 * @param  numberSize: length in bytes of the random number
 * @return TRUE on success, FALSE for error */
Enable_Secure_Boot_Status_Type SecLib_RandomGenerate(uint8* pNumber, uint32 numberSize);

/* Generate a MAC using the Key indicated by KeyId
 * @param  keyId: is the key ID being loaded to compute CMAC (RAM KEY, BOOT_MAC_KEY, KEY_1 only allowed)
 * @param  pMACdata: contains the pointer to the data for which the MAC shall be computed.
 * @param  lenMACdata: contains the number of bytes for the MAC generation.
 * @param  pMACresult: contains the pointer to the data where the MAC shall be stored.
 * @param  pMACLen [in,out] : holds a pointer to the memory location in which the output length in bytes is stored.
 *           On calling this function, this parameter shall contain the size of the buffer provided by macPtr.
 *           When the request has finished, the actual length of the returned MAC shall be stored.
 * @return TRUE when the MAC is generated correctly, FALSE on error */
Enable_Secure_Boot_Status_Type SecLib_MACGenerate(const SecLib_KeyIdSHEType keyId, const uint8* pMACdata, const uint32 lenMACdata, uint8* pMACresult, uint32* pMACLen);

/* Verify a MAC using the Key indicated by KeyId
 * @param  keyId: is the key ID being loaded to compute CMAC (RAM KEY, BOOT_MAC_KEY, KEY_1 only allowed)
 * @param  pMACdata: contains the pointer to the data for which the MAC shall be computed.
 * @param  lenMACdata: contains the number of bytes for the MAC generation.
 * @param  pMACToVerify: contains the pointer to the MAC to be verified
 * @param  lenMacToVerify: contain the MAC length
 * @return TRUE when the MAC is verified, FALSE on error */
Enable_Secure_Boot_Status_Type SecLib_MACVerify(const SecLib_KeyIdSHEType keyId, const uint8* pMACdata, const uint32 lenMACdata, const uint8* pMACToVerify, const uint32 lenMacToVerify);

/* Load keys into the SHE via CSM
 * @param  keyData : contains
 *         - keyId: is the key ID being loaded
 *         - authKeyId: is the authenticating key ID which is typically the Master_ECU_Key ID or keyId
 *         - UID: is the unique device ID. set equal to UID_WILDCARD will use the wildcard option for the UID
 *         - keyCounter: 28bit counter (CID)
 *         - keyFlags: 6bit key flag (FID) last 2 bits are 0)
 *         - plainTextKey: 16 bytes plain text key which is being loaded
 * @return the status of the operation (OPERATION_SUCCESSFUL for success) */
Enable_Secure_Boot_Status_Type SecLib_KeySHEUpdate(const SecLib_KeyDataType keyData);

/* Load RAM key via CSM. Available to the IPC SecOC compatibility adapter;
 * it loads the 16-byte value into the ICUS RAM key slot. The caller must
 * ensure that the slot is not concurrently used by another service.
 * @param  pKeyRam: pointer to 16 bytes plain text key which is being loaded
 * @param  keyRamLen: length of the KEY_RAM (always 16 bytes)
 * @return the status of the operation (OPERATION_SUCCESSFUL for success) */
Enable_Secure_Boot_Status_Type SecLib_KeyRAMUpdate(const uint8* pKeyRam, const uint8 keyRamLen);

#if defined(CLI)
FUNC(uint32, CRC_CODE) SecLib_Crc_CalculateCRC32(Crc_DataRefType Crc_DataPtr, uint32 Crc_Length, uint32 Crc_StartValue32, boolean Crc_IsFirstCall);
#endif
#endif /* SECURITYLIB_H */
