# DaVinci configuration: Crypto containers for vKeyM_MPKA

## Scope and assumptions

This document covers the Vector `Crypto_30_CryWrapper` configuration used as the key-storage/provider layer for `vKeyM_MPKA`. The active ECUC project uses AUTOSAR-standard CSM and CryIf definitions, while project-owned CSM/CryIf code owns the `Csm_*` and `CryIf_*` symbols MPKA calls. The wrapper BSWMD in this workspace refines `/AUTOSAR/EcucDefs/Crypto`; use the exact refined definition/package pair loaded by DaVinci.

The IPC use case documented here is key negotiation group 2 with two present members (local member 3 and remote EVCU member 4), P-224/secp224r1, X9.63/SHA-256 key derivation, and a 16-byte SecOC key. Since this is a two-member group, MPKA selects ECDH; it does not use the ECBD second-public-key round. The agreed `Z` representation is 56 bytes: x-coordinate followed by y-coordinate, each big endian, per the user's CS.00172 REQ 5.7.2 interpretation. Verify both ECUs and the active provider use that same representation. In this project, ECC is software mbedTLS ECP; ICUSE is used by the RNG bridge and for the separate symmetric/SHE services, not for hardware ECDH. The checked-in wrapper's `Hw_KeyExchangeCalcSecret` accepts only a 56-byte peer point and therefore only demonstrates this ECDH call shape; it does not establish ECBD support.

Use the **Minimal IPC ECDH profile** below for this ECU. The **Optional ECBD profile** is only for a build that can have three or more present group members and whose selected provider supports the MPKA ECBD path. The number of configured `CryptoKeyElement` definitions is not a statement that every element must be physically stored in HPSE: public values and non-secret metadata may be held outside HPSE where the IPC architecture requires it. Private scalars, shared-secret values, derived message-group keys, and operations using those secrets remain subject to the HPSE requirements in SD.00136 and CS.00172. Configure the secret element backing/storage accordingly; software `Persist` alone does not provide HPSE protection.

The workspace PC has no DaVinci Configurator or target compiler. This is a configuration guide, not a generated ECUC export or compilation result. Container names and option names below follow the checked-in wrapper BSWMD; validate them against the active licensed package and AUTOSAR release. Do not use Vector-specific options that are absent from the active definition.

I reviewed the five screenshots under `docs/config_images` and the supplied wrapper BSWMD/source. The visible MPKA-named rows currently under `CryptoKeyElements` show element ID 7, size 64, partial access enabled, persistence disabled, and read access `RA_ALLOWED`. Those rows do not define the elements MPKA calls by ID and size. Reconfigure/replace them with the element-by-element layout in this document, after checking whether the current rows are referenced anywhere. The visible `CryptoKeyTypes` table shows SHE/generic types but no MPKA exchange/KDF/MAC types; the visible `CryptoKeys` table likewise does not show the four MPKA key instances. Add or confirm those in their distinct containers.

The local wrapper Technical Reference PDF is version 2.4.0 and documents older key-management APIs as compatibility-only. The checked-in `Implementation` sources contain newer/custom functional key-management and software ECC/KDF paths. For these MPKA settings, use the active BSWMD plus the selected source implementation as the working reference; confirm the exact delivered package version before generation because the public KeyDerive header and hardware implementation currently disagree about algorithm/label elements.

## Build the Crypto-side key objects

Create the Crypto objects before adding CryIf references. Use distinct objects for every role; do not reuse SHE objects or another group's key.

| Crypto object | Suggested short name | Referenced type | Contents |
|---|---|---|---|
| Negotiation group key | `CryptoKey_MPKA_G2_Exchange` | Active MPKA exchange template with ECDH support (the TR names `KeyExchange_NISTP224R1_BD`) | P-224 private scalar, shared value, algorithm selector and MPKA member metadata; public points are passed through the MPKA session buffers |
| KDF input key | `CryptoKey_MPKA_G2_KdfInput` | `MPKA_KdfInput_X963_SHA256` | 56-byte PASSWORD and 1-byte SecOC SALT for the checked-in `Hw_KeyDerive` implementation |
| Temporary message-group key | `CryptoKey_MPKA_G2_TmpMac` | `MPKA_MacKey_AES128` | 16-byte output element written by key derivation |
| Final message-group key | `CryptoKey_MPKA_G2_FinalMac` | `MPKA_MacKey_AES128` | 16-byte committed SecOC key |

The Vector MPKA Technical Reference names the exchange template `KeyExchange_NISTP224R1_BD`; the screenshots show no such type in the visible `CryptoKeyTypes` table. For the two-member IPC profile, use that template only if the selected package supports the ECDH mode and the reduced element layout below. If the active template mandates additional elements, retain those exact delivered elements and include them in cleanup as required by that package. Keep temporary and final key types compatible with `Csm_KeyCopy`. The temporary and final MAC keys must be distinct CryptoKey instances even though they use the same MPKA MAC type.

## Configure `CryptoGeneral`

The wrapper BSWMD exposes these relevant module-level settings under `Crypto/CryptoGeneral`:

| Option | Recommended treatment |
|---|---|
| `CryptoDevErrorDetect` | Enable in development if consistent with project practice; apply release policy for production. |
| `CryptoVersionInfoApi` | Enable only if the ECU needs `Crypto_GetVersionInfo`; it does not create key references. |
| `CryptoMainFunctionPeriod` | Preserve the established scheduling value. MPKA's direct key APIs are synchronous in the checked-in flow; this period concerns main-function/job processing. |
| `CryptoSafeBswChecks` | Set according to the ECU safety concept and partition/ASIL allocation. |
| `CryptoNvMBlockDescriptor` | Set to the active NvM block descriptor used for persisted Crypto key storage. The MPKA temporary/final keys are required to persist, so this reference and the NvM block must exist if this wrapper owns their storage. |
| `CryptoNvMEnableSetRamBlockStatus` | Set `true` when using this wrapper's NvM path for MPKA temp/final keys. The checked-in `KeyValidSet` implementation calls NvM `SetRamBlockStatus` behind this switch; MPKA sets keys valid after writes/copies. Confirm the NvM block descriptor is the intended one. |
| `CryptoUserConfigFile` | Preserve the project's configured file or leave unset if unused. It is unrelated to key-reference resolution. |

Preserve the existing SHE configuration. Add MPKA persistence to the correct NvM descriptor without changing SHE key/update settings. Software-persisted Crypto key elements are not thereby SHE-protected. If the project has no approved NvM path for persisted MPKA keys, the configuration cannot meet the MPKA key-lifecycle requirement as written; resolve storage ownership before generation.

## Configure `CryptoWrapperGeneral`

The screenshots show the Vector wrapper extension container. Keep its existing RH850/ICUSE and SHE settings; this MPKA software ECDH path does not need a new hardware ECC primitive or a different SHE key-update setup.

| Option | Action for this use case |
|---|---|
| `CryptoKeyIdMapping` | Preserve the current setting required by the configured underlying CRY. This maps Crypto key IDs to low-level CRY IDs; it is not a CSM↔CryIf↔Crypto reference mapping. |
| `CryptoKeyUpdateScheme` | Preserve the current SHE key-update scheme. MPKA does not change it. |
| `CryptoSecondKeyPageOffset` | Preserve the value required by the active CRY/derivative; do not copy a value from another target. |
| `CryptoUseKeyExtractForPlaintextKey` | Preserve the current SHE/key-extract integration setting. |
| `CryptoProvideBufferInBlockFinish`, `CryptoProvideIdInsteadOfPointer` | Preserve according to the active CRY interface version; unrelated to direct MPKA key-management calls. |
| `CryptoProvideCsmNotificationApi` | Leave at the existing setting (the checked-in BSWMD default is false). Enable only for an actual CRY callback integration, and first verify it will not introduce a second owner for any custom CSM callback symbol. |
| `CryptoRamKeyLifeCycleSupport`, `CryptoCallFinishAfterError`, `CryptoProofBufferPointerSupport` | Preserve the existing SHE/CRY behavior; do not change for MPKA. |

The checked-in BSWMD lists these as Vector wrapper/CRY compatibility options. If a field is absent from the active version, do not add it. The config screenshot of `CryptoSymDecryptConfig_ECB` references `Cry_30_Rh850Icus.h` and CSM decrypt jobs; leave that existing job configuration intact.

## Step-by-step in DaVinci

1. Open the existing `Crypto_30_CryWrapper` module instance and confirm the refined standard Crypto definition matches the installed wrapper package. Keep the current ICUSE/SHE module configuration.
2. Open `Crypto/CryptoGeneral`. Preserve diagnostics, version API, task period and safe-check settings. Configure the Crypto NvM descriptor and enable `CryptoNvMEnableSetRamBlockStatus` for the persistent MPKA temp/final key element.
3. Open `Crypto/CryptoKeyElements/CryptoKeyElement`. Check the four current MPKA-looking rows shown in the screenshot. Each currently appears as a single element with ID 7, size 64, partial access on, persistence off and `RA_ALLOWED`. They cannot implement the required per-element layout. If unused placeholders, remove them; otherwise repurpose/replace them after updating all references. For the Minimal IPC ECDH profile create the eight definitions in its table below. Add the two elements in the Optional ECBD profile only when that protocol is supported by the selected build. Set the exact element ID, size, partial, persist, read, write, initial value and virtual-target fields as listed.
4. Open `Crypto/CryptoKeyTypes/CryptoKeyType`. Create three types: one exchange type referencing the five Common exchange elements and, for ECBD builds, the two ECBD-only partner-public elements; one KDF-input type referencing PASSWORD and SALT; and one MAC type referencing the 16-byte MAC element. The visible screenshot lists only generic/SHE types, so create these if they are not hidden elsewhere. Do not put multiple key elements under one ID 7.
5. Open `Crypto/CryptoKeys/CryptoKey`. Create four instances, each with a unique `CryptoKeyId` and the type reference shown below. The visible screenshot's table shows existing SHE/system keys but no MPKA instances in the visible rows; add/confirm the four MPKA instances here. Allocate IDs from the active project after checking all existing IDs and wrapper reservations.
6. Leave `Crypto/CryptoPrimitives`, `CryptoDriverObjects`, `CryptoWrapper` job configurations and the current `Crypto_30_Rh850Icus` associations as they are. MPKA calls the direct key-management APIs; adding AES/KDF/ECDH primitives or CSM jobs does not make those direct calls resolve.
7. Verify references and generated values: each key has the correct type; each type references all required elements; each element ID and capacity matches the table; the custom CSM registry maps the generated Crypto IDs; the final MPKA CDD still points through CSM/CryIf to these keys.

The existing wrapper `CryptoDriverObject` is for job-based primitives and must satisfy its own package constraints. The checked-in schema fixes `CryptoDriverObjectQueueSize=1` and the wrapper documentation says the driver does not support queued jobs. Preserve that configuration; it is not a reason to create a new object for MPKA.

## Configure `CryptoKeyElements/CryptoKeyElement`

The wrapper BSWMD defines these fields per element: `CryptoKeyElementId`, `CryptoKeyElementSize` (bytes), optional `CryptoKeyElementInitValue`, `CryptoKeyElementAllowPartialAccess`, `CryptoKeyElementPersist`, `CryptoKeyElementReadAccess`, `CryptoKeyElementWriteAccess`, and optional `CryptoKeyElementVirtualTargetRef`.

Use the following exact capacities. The `CryptoKeyElementId` values for standard elements are the AUTOSAR/Crypto IDs used by the checked-in sources. Get each `CUSTOM_*` value from the active Vector/CSM headers or delivered key template. The supplied Crypto folder does not define those custom IDs. Do not keep assigning ID 7 to all four rows shown in the screenshot.

### Minimal IPC ECDH profile

Configure these eight elements for the IPC two-member group.

| Suggested element short name | Element role / ID constant | `CryptoKeyElementId` | Size | Partial | Persist | Read | Write | Init / virtual target |
|---|---|---:|---:|---|---|---|---|---|
| `MPKA_KeyEx_PrivKey` | `CRYPTO_KE_KEYEXCHANGE_PRIVKEY` | 9 | 28 B | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |
| `MPKA_KeyEx_SharedValue` | `CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE` | 1 | **56 B** | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |
| `MPKA_KeyEx_Algorithm` | `CRYPTO_KE_KEYEXCHANGE_ALGORITHM` | 12 | 1 B | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |
| `MPKA_KeyEx_NumEcu` | `CRYPTO_KE_CUSTOM_KEYEXCHANGE_NUM_ECU` | Exact Vector ID | 1 B | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |
| `MPKA_KeyEx_EcuId` | `CRYPTO_KE_CUSTOM_KEYEXCHANGE_ECU_ID` | Exact Vector ID | 1 B | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |
| `MPKA_KDF_Password` | `CRYPTO_KE_KEYDERIVATION_PASSWORD` | 1 | **56 B** | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |
| `MPKA_KDF_Salt` | `CRYPTO_KE_KEYDERIVATION_SALT` | 13 | 1 B | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |
| `MPKA_MacKey` | `CRYPTO_KE_MAC_KEY` / output element ID 1 | 1 | 16 B | false | **true** | **`RA_ALLOWED` for the checked-in SecOC adapter** | `WA_ALLOWED` | Empty / unset |

### Optional ECBD profile

For a build that supports groups of three or more present members, add these two elements to the exchange type. The selected provider must support the MPKA ECBD second-public-key round; the checked-in wrapper implementation does not establish this support.

| Suggested element short name | Element role / ID constant | `CryptoKeyElementId` | Size | Partial | Persist | Read | Write | Init / virtual target |
|---|---|---:|---:|---|---|---|---|---|
| `MPKA_KeyEx_PartnerPubKey` | `CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY` | Exact Vector ID | 56 B | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |
| `MPKA_KeyEx_PartnerPubKey2` | `CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY_2` | Exact Vector ID | 56 B | false | false | `RA_DENIED` | `WA_ALLOWED` | Empty / unset |

The Minimal IPC ECDH profile uses eight CryptoKeyElement definitions: five exchange elements, two KDF inputs, and the MAC key. The optional ECBD profile adds only the two partner-public-key elements used when generating the second public key. `OWNPUBKEY` is not needed by the checked-in implementation: `Csm_KeyExchangeCalcPubVal` returns the public point through its output buffer into MPKA session data. `INTERMEDIATE` is not written or read by the checked-in MPKA/wrapper implementation; add it only if the exact delivered provider proves it is required, and then update its cleanup path too. The peer public point in ECDH is passed directly as the `Csm_KeyExchangeCalcSecret` input argument, so it does not need a CryptoKeyElement in this profile.

These settings are for this SecOC flow and the checked-in wrapper implementation. The provider internally reads/writes the private scalar, shared value, KDF input and output. The wrapper's external `KeyElementGet` path rejects `RA_DENIED`; its local `KeyElementCopy` copies within the driver without turning those secret elements into plaintext reads. The external `KeyElementSet` path requires `WA_ALLOWED`, which MPKA needs because it clears the elements using explicit `Csm_KeyElementSet` calls. If the custom CSM emulates copy by `KeyElementGet` plus `KeyElementSet` rather than forwarding to the wrapper's internal copy API, this access recommendation will not work; implement the proper internal copy path.

**MAC-key read exception for the checked-in ECU path:** `security/source/crypto_lib/secoc_securitylib_csm_wrapper.c` implements `SecOcSecurityLib_ActivateMessageGroupKey()` by calling `Csm_KeyElementGet(finalMessageGroupCsmKeyId, CRYPTO_KE_MAC_KEY, ...)`, then loading the 16-byte result into ICUSE RAM with `SecLib_KeyRAMUpdate()`. Therefore the shared `MPKA_MacKey` element definition must use `CryptoKeyElementReadAccess=RA_ALLOWED` while this adapter is used. Because both temporary and final key objects refer to this same element definition/type, both will be readable through the public key API. Treat that as an intentional plaintext key-export path and ensure the custom CSM enforces caller authorization and wipes temporary buffers. If the product security design requires a non-readable key, replace this adapter route with the standard CSM job-to-key activation path and only then set the key element to `RA_DENIED`; do not leave the current adapter enabled with `RA_DENIED` and expect activation to succeed.

Set `CryptoKeyElementAllowPartialAccess=false` for these exact lengths. The SecOC branch sets SALT to exactly 1 byte; the 56-byte PASSWORD receives the 56-byte shared value. Do not enable partial access as a workaround for the current 64-byte rows in the screenshot; correct their capacity instead.

The checked-in MPKA source also contains an optional MACsec path that writes a two-byte SALT (prefix plus negotiation-group ID). If `VKEYM_MPKA_SUPPORT_MACSEC_KEY_NEGOTIATION` is enabled in this ECU and the same KDF-input key is used for that path, configure the SALT element capacity as 2 bytes and `AllowPartialAccess=true`: SecOC writes 1 byte, while MACsec writes 2, and the wrapper preserves the actual written length for KDF input. For the requested SecOC-only feature set, use the 1-byte / partial-access-false row in the table.

There are no algorithm/label element rows in the base layout for the checked-in `Crypto_30_CryWrapper_Hw_KeyDerive`: it reads PASSWORD and SALT and hard-codes X9.63/SHA-256. Its public `Crypto_30_CryWrapper_KeyDerive` header nevertheless documents algorithm and custom-label elements. Reconcile that mismatch against the selected release. If the active header/template requires these, add the exact non-secret element IDs/sizes and update/confirm the implementation; do not add guessed unused elements.

### Why these per-element access and persistence values

The MPKA Technical Reference says the KDF-input key does not need persistence and the temporary/final derived keys must be persisted. It does not say the negotiation-group exchange key must persist. Therefore set all exchange and KDF-input elements to `CryptoKeyElementPersist=false`; set the dedicated MAC element used by both temporary and final key objects to `true`. This avoids persisting the ephemeral P-224 scalar and shared secret while meeting the documented temp/final-key persistence requirement. If product requirements require key-negotiation resume across reset, assess that separately and do not silently persist private/shared elements.

The checked-in wrapper code makes the access settings concrete: `Crypto_30_CryWrapper_Local_KeyElementSet` permits public `KeyElementSet` only for `WA_ALLOWED`; MPKA uses that API to clear the private/shared elements and, for ECBD groups, the two partner-public elements. `Crypto_30_CryWrapper_Local_KeyElementCopy` copies directly between configured elements without using plaintext Get/Set access. The public `KeyElementGet` path rejects reads unless `RA_ALLOWED`; internal ECC/KDF functions use internal local access. Thus, set `WriteAccess=WA_ALLOWED` on all MPKA elements, keep `ReadAccess=RA_DENIED` for exchange and KDF elements, and use the MAC-key exception above for the active compatibility adapter. If the custom CSM implements element copy via public Get/Set calls instead of forwarding to the wrapper's internal `KeyElementCopy`, change that implementation seam rather than making every secret element readable.

Because the temporary/final key element is persisted, set `CryptoGeneral/CryptoNvMBlockDescriptor` to the Crypto-key NvM descriptor and `CryptoNvMEnableSetRamBlockStatus=true`, subject to the active NvM integration. The wrapper's `KeySetValid` calls `NvM_SetRamBlockStatus` only when the switch is enabled. Software persistence does not make the data SHE-protected. The final key remains software key material until a separate approved activation flow loads it into ICUSE `RAM_KEY`.

`SheNvmKey` and `SheRamKey` in the checked-in configuration are SHE-oriented virtual elements (64-byte persisted SHE storage and 16-byte non-persistent RAM slot, respectively). They are not storage for the 56-byte software ECDH values. Keep them for existing SHE services; create ordinary non-virtual key elements for MPKA.

## Configure `CryptoKeyTypes/CryptoKeyType`

For each type, add one `CryptoKeyElementRef` per element that the key object exposes. Element IDs are interpreted within the referenced key/type, so equal IDs across different layouts are normal (for example, PASSWORD ID 1 and MAC key ID 1).

1. **Exchange type:** for Minimal IPC ECDH, reference the five exchange elements: scalar, shared value, algorithm, member count and local member position. For an ECBD-capable build, additionally reference both partner-public elements. Do not reference own-public or intermediate elements unless the exact selected provider consumes them.
2. **KDF-input type:** reference PASSWORD and SALT for the checked-in hardware implementation. Only add algorithm/label elements if the active wrapper release's actual implementation and generated key template require them; the current source header comment and `Hw_KeyDerive` body disagree.
3. **MAC type:** reference only the 16-byte MAC key element (ID 1).

## Configure `CryptoKeys/CryptoKey`

Create four unique instances with unique `CryptoKeyId` values and mandatory `CryptoKeyTypeRef` settings:

| Instance | `CryptoKeyTypeRef` |
|---|---|
| `CryptoKey_MPKA_G2_Exchange` | ECDH exchange type for the Minimal IPC profile; use the ECBD-capable exchange type only for an ECBD build |
| `CryptoKey_MPKA_G2_KdfInput` | KDF-input type |
| `CryptoKey_MPKA_G2_TmpMac` | MAC type |
| `CryptoKey_MPKA_G2_FinalMac` | MAC type |

Persist policy is on each referenced element definition, not the CryptoKey instance. Keep CSM, CryIf and Crypto ID namespaces distinct.

## Driver objects and job-based consumers

The checked-in wrapper defines `CryptoDriverObjects/CryptoDriverObject` with `CryptoDriverObjectId`, `CryptoDriverObjectQueueSize`, and one or more `CryptoPrimitiveRef` entries. Preserve the existing SHE/job configuration. The local wrapper BSWMD fixes its queue size at 1 and documents no queue support.

MPKA calls direct key-ID functions (`KeyElementSet/Copy`, `KeyCopy`, `KeySetValid`, `KeyExchangeCalcPubVal/Secret`, and `KeyDerive`). Do not add `CryptoPrimitive`/driver-object entries solely to make these calls work. Configure primitives and driver-object associations only for real job-based clients in the ECU; follow the installed schema if its multiplicities require an object even when this MPKA flow does not use it.

## Wrapper API contract to resolve

The checked-in `Crypto_30_CryWrapper_KeyDerive` header says the input key contains PASSWORD, SALT, `CRYPTO_KE_KEYDERIVATION_ALGORITHM`, and `CRYPTO_KE_CUSTOM_KEYDERIVATION_LABEL`. The checked-in `Crypto_30_CryWrapper_Hw_KeyDerive` implementation reads only PASSWORD and SALT and hard-codes X9.63/SHA-256. For the body currently in this workspace, configure the KDF key type with only PASSWORD and SALT. Before generation, reconcile the header/template mismatch against the exact package selected for this ECU; if that release's active implementation actually reads the algorithm/label elements, add their delivered elements and exact values then. Do not guess IDs or populate unused fields.

The wrapper's `Hw_*` routines are provider hooks called by the wrapper. They are not CSM/CryIf callbacks. Confirm the build manifest includes the wrapper key-management sources under `component/Crypto_30_CryWrapper/Implementation` and the configured key storage, then make the custom CSM/CryIf facade dispatch through the supported Crypto public APIs. Folder presence alone does not establish that the implementation is selected in the build.

## Generation review checklist

1. Confirm DaVinci resolves all `CryptoKeyTypeRef` and `CryptoKeyElementRef` targets in the loaded refined Crypto definition.
2. Confirm generated key IDs, element IDs, capacities and access/persistence values match the reviewed mapping; do not copy IDs from another ECU or release.
3. Confirm the ECDH provider writes 56-byte `x||y`, and the KDF receives exactly those 56 bytes and a one-byte SecOC salt.
4. Confirm final/temporary keys have 16-byte capacity and are compatible for key-copy/commit behavior.
5. Preserve existing SHE settings. Keep exchange and KDF-input elements non-persistent; persist the dedicated 16-byte MAC element used by both temporary and final MPKA key objects, and confirm the Crypto NvM descriptor and dirty-block update path are configured.
6. Check the CSM/CryIf facade mapping against all generated Crypto IDs. DaVinci generation and target verification remain to be done on the IPC build PC.

## Related documents

- [Overall DaVinci key-reference guide](davinci-vkeym-mpka-csm-cryif-crypto-guide.md)
- [CryIf container configuration](davinci-vkeym-mpka-cryif-container-configuration.md)
- [CSM container configuration](davinci-vkeym-mpka-csm-container-configuration.md)
- Local wrapper schema: `component/Crypto_30_CryWrapper/BSWMD/Crypto_30_CryWrapper_bswmd.arxml`
- Local provider implementation: `component/Crypto_30_CryWrapper/Implementation/Crypto_30_CryWrapper_Hw.c`
- Local MPKA key flow: `component/vKeyM_MPKA/Implementation/vKeyM_MPKA_CryptoStateMachine.c`
