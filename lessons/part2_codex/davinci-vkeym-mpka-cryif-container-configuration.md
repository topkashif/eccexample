# DaVinci configuration: CryIf containers for vKeyM_MPKA

## Scope and assumptions

This document covers CryIf ECUC data connecting standard CSM keys to Crypto keys. The project's custom CryIf implementation owns any `CryIf_*` symbols MPKA calls; configuring CryIf containers does not supply that runtime code. The active ECUC project uses the AUTOSAR-standard CryIf definition, not the Vector CryIf runtime package. Use the exact AUTOSAR release and the parameter/reference paths exposed in the active DaVinci project.

For this IPC flow, four Crypto objects are expected: group 2 exchange state, KDF input, temporary SecOC MAC key and final SecOC MAC key. The Crypto definition is provided by `Crypto_30_CryWrapper`, whose checked-in BSWMD refines the standard `/AUTOSAR/EcucDefs/Crypto` module definition. Confirm that DaVinci loaded a compatible refined Crypto definition so `CryIfKeyRef` can reference those keys.

This PC has no DaVinci Configurator or target compiler. These are detailed configuration instructions, not generated ECUC data or compile results. The checked-in CryIf BSWMD is a schema reference; if it exposes vendor extensions absent from the project's standard definition, do not add them unless the active schema/runtime consumes them.

## CryIf configuration role

The intended key mapping is:

```text
CsmKey.CsmKeyRef -> CryIfKey
CryIfKey.CryIfKeyRef -> CryptoKey in Crypto_30_CryWrapper
```

MPKA's CDD references target CSM keys. The custom CSM resolves `CsmKeyId`; custom CryIf resolves `CryIfKeyId` and dispatches key-management calls to the selected Crypto implementation. Keep each ID namespace independent. A CryIf key reference is not a channel or job route.

## Configure CryIf general settings

The local schema exposes `CryIfGeneral` with these relevant switches; use only fields available in the active AUTOSAR definition:

| Option | Configuration guidance |
|---|---|
| `CryIfDevErrorDetect` | Enable in development if consistent with project diagnostics; select the production setting per project policy. |
| `CryIfSafeBswChecks` | Enable as required by the safety concept and partition/ASIL allocation. The checked-in Vector BSWMD describes it as required for safety-mapped CryIf components. |

These switches do not create key mappings or implement CryIf API behavior. Keep generated settings aligned with the custom runtime's diagnostics/safety behavior.

## Configure `CryIfKeys/CryIfKey`

Create one CryIf key for every Crypto key used by MPKA. The local CryIf BSWMD makes `CryIfKeyId` and `CryIfKeyRef` mandatory. Use unique symbolic names and IDs allocated by the IPC project.

| CryIf key short name | Role | `CryIfKeyId` | `CryIfKeyRef` |
|---|---|---|---|
| `CryIfKey_MPKA_G2_Exchange` | Negotiation group state | Unique CryIf ID | `CryptoKey_MPKA_G2_Exchange` |
| `CryIfKey_MPKA_G2_KdfInput` | KDF password/salt | Unique CryIf ID | `CryptoKey_MPKA_G2_KdfInput` |
| `CryIfKey_MPKA_G2_TmpMac` | Temporary 16-byte output | Unique CryIf ID | `CryptoKey_MPKA_G2_TmpMac` |
| `CryIfKey_MPKA_G2_FinalMac` | Committed 16-byte SecOC key | Unique CryIf ID | `CryptoKey_MPKA_G2_FinalMac` |

In DaVinci, select the target by symbolic reference to the correct CryptoKey; do not enter a coincidental numeric Crypto ID as a substitute. If the reference chooser cannot see the wrapper Crypto keys, resolve the AUTOSAR release/refined-module-definition mismatch before generation.

Record the runtime mapping explicitly:

| CSM key | CSM ID | CryIf key | CryIf ID | Crypto key | Crypto ID |
|---|---:|---|---:|---|---:|
| Exchange | fill from active project | Exchange | fill from active project | Exchange | fill from active project |
| KDF input | fill from active project | KDF input | fill from active project | KDF input | fill from active project |
| Temporary MAC | fill from active project | Temporary MAC | fill from active project | Temporary MAC | fill from active project |
| Final MAC | fill from active project | Final MAC | fill from active project | Final MAC | fill from active project |

The custom CSM/CryIf registry must mirror the generated ID and symbolic-reference mapping. At startup or table generation, reject duplicate IDs, missing targets, mismatched types and references to the wrong message/group object.

## Configure CryIf Crypto-module association only when applicable

Some CryIf definitions include a `CryIfCryptoModule` container associating an implementation module with the Crypto driver API. In the checked-in Vector BSWMD, that container includes a Crypto-module reference and compatibility options (for example API include/prefix and key-valid API naming). The custom CryIf is not the Vector implementation, so:

1. If the active standard definition/runtime consumes a module-association container, point it to the configured Crypto wrapper module and use the exact interface naming required by the compiled wrapper API.
2. If the active AUTOSAR definition does not expose it, do not add a Vector-only container to imitate it.
3. If custom CryIf bypasses generated dispatch data, keep provider registration in the project's own table and document which data is generated versus handwritten.
4. Verify key-management services use the wrapper's public Crypto APIs and that its key IDs address the same configured CryptoKey objects.

Never treat `Crypto_30_CryWrapper_Hw_*` functions as CryIf callbacks. They are provider hooks called from inside the wrapper. The custom CryIf should dispatch through the wrapper's supported public API or an explicitly designed provider seam.

## Configure channels only for job-based clients

MPKA's checked-in crypto state machine calls direct key-ID services: `Csm_KeyExchangeCalcPubVal`, `Csm_KeyExchangeCalcSecret`, `Csm_KeyDerive`, `Csm_KeyElementSet`, `Csm_KeyElementCopy`, `Csm_KeyCopy`, and `Csm_KeySetValid`. These calls need the key mapping above; a `CryIfChannel` does not route them.

For another client that uses job APIs (for example a job-based SecOC MAC), create a channel only as required by the active CryIf schema and runtime. The checked-in schema has:

| Container/field | Setting |
|---|---|
| `CryIfChannel` short name | Unique name identifying the job path/provider channel |
| `CryIfChannelId` | Unique channel ID in the CryIf namespace |
| `CryIfDriverObjectRef` | Symbolic reference to the Crypto driver object used by that job path |

The related CSM queue references the channel. A job path is separate from the CDD direct key-reference path. If the active schema enforces a minimum channel/module container even when no MPKA call uses it, satisfy DaVinci's consistency rule with a valid project object, but do not represent that object as the dispatch route for MPKA key-ID operations.

## Custom runtime responsibilities

The project-owned CryIf layer must, for the direct key-management API subset MPKA uses:

1. Resolve each CryIf ID to the matching Crypto key/provider descriptor.
2. Forward or implement element set/copy, key copy, key valid, public-value calculation, shared-secret calculation and key derivation with the expected AUTOSAR return/error semantics.
3. Preserve wrapper access-control and key-validity behavior; ensure CSM key handles and wrapper Crypto key storage refer to the same underlying elements.
4. Prevent duplicate ownership of `CryIf_*` symbols. Do not link a Vector CryIf implementation beside the custom API implementation.
5. Keep the active key storage consistent with the configured software P-224 ECDH path. ICUSE RNG/symmetric services do not turn ECDH into hardware ECC.

If a custom CryIf dispatches directly to a provider hook, it also assumes responsibility for the validation, data mapping, initialization, and lifecycle normally enforced by the wrapper's public boundary.

## Generation review checklist

1. Check every `CryIfKeyRef` resolves to the intended wrapper CryptoKey in the loaded DaVinci schema.
2. Check CryIf IDs are unique and separately allocated from CSM/Crypto IDs, MPKA group/member/message-group IDs, and job IDs.
3. Compare generated CryIf mappings with the custom runtime registry and the CSM table.
4. Confirm job channels and module associations only where the actual job/runtime path needs them; observe active schema multiplicities.
5. Audit the link manifest/map for a single owner of each `CryIf_*` API symbol and confirm wrapper key APIs/storage are included.

## Related documents

- [Overall DaVinci key-reference guide](davinci-vkeym-mpka-csm-cryif-crypto-guide.md)
- [Crypto container configuration](davinci-vkeym-mpka-crypto-container-configuration.md)
- [CSM container configuration](davinci-vkeym-mpka-csm-container-configuration.md)
- Local schema: `component/CryIf/BSWMD/CryIf_bswmd.arxml`
- Local AUTOSAR CSM/CryIf/Crypto specifications: `docs/AUTOSAR_SWS_CryptoServiceManager.pdf`, `docs/AUTOSAR_SWS_CryptoInterface.pdf`, `docs/AUTOSAR_SWS_CryptoDriver.pdf`
