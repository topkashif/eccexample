# ECDH key elements for the IPC ECU

## Finding

For the repository's current vKeyM_MPKA SecOC path, one ECU-generated ephemeral ECDH key pair, the peer's public point, the ECDH shared value, and one derived MAC key are the cryptographic material. The configuration has more `CryptoKeyElement`s because AUTOSAR represents operation inputs, outputs, and vendor protocol state as elements. These entries are not all additional provisioned keys.

This assessment treats “IPC ECU” as the ECU using this repository's two-member vKeyM_MPKA ECDH flow. The checked-in implementation is P-224 (`secp224r1`) and derives the SecOC message-group MAC key. It is a project-specific baseline, not a universal IPC profile.

## Material used by the two-member flow

| Purpose | AUTOSAR element / key | Current profile | Required handling |
|---|---|---:|---|
| Local ephemeral private scalar | Negotiation key: `CRYPTO_KE_KEYEXCHANGE_PRIVKEY` (ID 9) | 28 bytes | Generated for the exchange; secret, protected from read/export, and zeroized after use. Do not provision as a long-term key. |
| Local ephemeral public point | Negotiation key: `CRYPTO_KE_KEYEXCHANGE_OWNPUBKEY` (ID 10) | 56 bytes (`X || Y`) | Public output. vKeyM also clears this element during cancellation. |
| Peer ephemeral public point | Input to `Csm_KeyExchangeCalcSecret` | 56 bytes (`X || Y`) | Supplied as the API's `partnerPublicValuePtr`; the checked-in wrapper does not require a separate standard peer-public-key element. Validate the point before computing. |
| ECDH shared value | Negotiation key: `CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE` (ID 1) | 56 bytes for this SecOC profile | Secret intermediate copied to the KDF input and later cleared. The wrapper supports a 28-byte x-coordinate for another profile, but that is not the configured SecOC message-group-key flow described here. |
| Exchange algorithm selector | Negotiation key: `CRYPTO_KE_KEYEXCHANGE_ALGORITHM` (ID 12) | 1 byte | vKeyM writes the P-224 ECDH selector. The curve is fixed by this repository's backend. |
| KDF input | KDF key: `CRYPTO_KE_KEYDERIVATION_PASSWORD` (ID 1), `CRYPTO_KE_KEYDERIVATION_SALT` (ID 13) | 56-byte shared value; 1-byte message-group ID | Transient input to X9.63/SHA-256; clear the password after derivation. |
| Derived message MAC key | Temporary and final MAC keys: element ID 1 (`CRYPTO_KE_MAC_KEY`) | 16 bytes each | The temporary key is the derive/commit buffer; the final key is the committed SecOC key. They have the same element layout and can share one `CryptoKeyType`, but remain separate `CryptoKey` instances. |

The AUTOSAR CSM API defines the peer public value as an argument to `Csm_KeyExchangeCalcSecret`, while `Csm_KeyExchangeCalcPubVal` returns the local public value through an output buffer. So a generic extra CryptoKeyElement for the remote public point is unnecessary for this wrapper. The local public-key element is still part of the active vKeyM key lifecycle because vKeyM clears it.

## vKeyM bookkeeping elements

The checked-in vKeyM state machine also references five custom elements on the negotiation key:

| Custom element | Value size | Why it appears |
|---|---:|---|
| `CRYPTO_KE_CUSTOM_KEYEXCHANGE_ECU_ID` | 1 byte | vKeyM stores the local member position. |
| `CRYPTO_KE_CUSTOM_KEYEXCHANGE_NUM_ECU` | 1 byte | vKeyM stores the member count and chooses ECDH versus ECBD. |
| `CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY` | 56 bytes | ECBD workflow buffer. |
| `CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY_2` | 56 bytes | ECBD workflow buffer. |
| `CRYPTO_KE_CUSTOM_KEYEXCHANGE_INTERMEDIATE` | 56 bytes | ECBD workflow intermediate. |

For exactly two members, the source selects ECDH and does not use the ECBD buffers to calculate the shared value. However, its cancel/cleanup function attempts to zero all three ECBD elements unconditionally. Removing them from an otherwise unmodified configuration can therefore make cleanup fail. They are implementation bookkeeping/work buffers, not three more long-term ECU keys. Removing them safely would require changing the vKeyM cleanup behavior and validating that change; for this source baseline, keep them configured.

The five custom macros are referenced by the source but are not defined in the checked-in `code/security/include/config/Csm_Types.h`. Their assigned IDs must be added consistently to the integration's C header and DaVinci configuration. Give each custom element a distinct ID within the negotiation key so the five values do not alias each other or the standard elements in that key. IDs are scoped by the CryptoKey: AUTOSAR intentionally reuses ID 1 for shared value, KDF password, and MAC key in different keys.

## Configuration count: keys versus types versus elements

For one key-negotiation group and one message group, the current lifecycle uses:

- **Three `CryptoKeyType` layouts:** negotiation key, KDF input key, and MAC key. The temporary and final MAC keys can share the same one-element MAC type.
- **Four `CryptoKey` instances:** negotiation, KDF input, temporary MAC key, and final MAC key.
- **Thirteen element slots in total:** nine in the negotiation key (four standard elements above plus five custom elements), two in the KDF input key, and one in each MAC key.

That count follows the checked-in vKeyM and wrapper behavior. It does not mean there are thirteen independent secret keys. The final 16-byte MAC key is the long-lived output of this flow; whether it is stored persistently is a separate approved key-storage decision. The ephemeral private scalar and shared value are temporary. If the integration uses more message groups, each group may need its own temporary/final output keys per the vKeyM references.

The ECDH and KDF path calls CSM key-management APIs directly. It does not need a CSM job/primitive entry for ECDH. Job and CryptoPrimitive configuration is a separate concern for consumers such as SecOC MAC generation/verification.

## Review of the supplied screenshots

The screenshot `config_images/WhatsApp Image 2026-10-01 at 17.19.45 (1).jpeg` appears to show four MPKA-labeled CryptoKeyElement definitions (`Exchange`, `KdfInput`, `TmpMac`, and `FinalMac`), each displayed with element ID 7 and size 64 bytes. If these are intended as the active element mappings, they do not match the checked-in implementation:

- The negotiation key needs separate standard elements with IDs 9, 10, 1, and 12, plus the five custom elements.
- The KDF input needs IDs 1 and 13.
- The temporary and final MAC targets use element ID 1 and 16-byte length in this profile.
- The shown four definitions do not expose the custom member-count/position and ECBD cleanup elements referenced by vKeyM.

The other screenshots show existing CryptoKeyTypes, CryptoPrimitives, and CryptoWrapper/SHE configuration; those are useful surrounding context but do not demonstrate the complete MPKA CryptoKeyType/instance mapping. The repository contains no configured DaVinci ECUC project ARXML, so the screenshots may be a partial/intermediate view. Verify against the active DaVinci project before changing values.

## Security and profile boundaries

NIST's ephemeral-key requirements say to use an ephemeral private key for one key-establishment transaction, protect it until destruction, and destroy it promptly; it must not be backed up or archived. This supports treating the ECDH scalar here as volatile transaction state, not as a provisioned persistent key. The checked-in vKeyM flow zeroizes it after calculation.

There is a configuration point to resolve with the Vector/platform owner: the existing vKeyM configuration guide notes that the Vector reference describes the negotiation `CryptoKey` as persistent, while the checked-in wrapper stores the ephemeral scalar in software key-element storage and NIST says an ephemeral private key must not be backed up or archived. Confirm whether “persistent” refers to the key object or other retained state rather than the ephemeral scalar; do not enable NVM persistence for that scalar without resolving this distinction.

The peer public point must be validated before ECDH. The checked-in `SecLib_EccComputeSharedSecret` path performs on-curve validation. ECDH by itself does not authenticate which ECU supplied that point; confirm the deployed MPKA protocol binds the exchanged public key to the intended ECU and satisfies the vehicle's key-confirmation/authentication requirements.

P-224 is the only curve implemented in this repository's checked-in ECC backend. Confirm that this legacy profile remains approved by the OEM/platform security policy before deploying it; a repository implementation constraint is not itself a security-policy approval.

## Primary sources and project evidence

- AUTOSAR, [Specification of Crypto Service Manager, R21-11](https://www.autosar.org/fileadmin/standards/R21-11/CP/AUTOSAR_SWS_CryptoServiceManager.pdf), §7.2.2.3 and §8.3.8.7.2: key-element identifiers and the public-value input/output signatures for key exchange.
- AUTOSAR, [Specification of Crypto Driver, R21-11](https://www.autosar.org/fileadmin/standards/R21-11/CP/AUTOSAR_SWS_CryptoDriver.pdf), §§7.2 and 10.1.9–10.1.10: CryptoKey references a CryptoKeyType; CryptoKeyType references CryptoKeyElements.
- NIST, [SP 800-56A Rev. 3](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final), §§5.6.3.3, 6.1.2.2, and 6.1.2.3: ephemeral key lifecycle, the two-ephemeral-key ECC agreement flow, and its identity/key-confirmation boundary.
- [Vector vKeyM_MPKA Technical Reference](../component/vKeyM_MPKA/Documentation/TechnicalReference_vKeyM_MPKA.pdf), §§5.3–5.7; [AUTOSAR CS.00172](../standards/CS_00172.pdf), §5.7.2, as selected by the existing integration guide.
- Project behavior: [`vKeyM_MPKA_CryptoStateMachine.c`](../component/vKeyM_MPKA/Implementation/vKeyM_MPKA_CryptoStateMachine.c), especially the ECDH path, KDF copy/derive, and cancel cleanup; [`Crypto_30_CryWrapper_Hw.c`](../component/Crypto_30_CryWrapper/Implementation/Crypto_30_CryWrapper_Hw.c), P-224 key generation, shared-value storage, and KDF; [`Csm_Types.h`](../code/security/include/config/Csm_Types.h), standard element IDs; and the existing [DaVinci configuration guide](davinci_vkeym_mpka_configuration.md).
