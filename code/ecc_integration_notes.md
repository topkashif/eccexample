# ECC Enablement for vKeyM_MPKA Key Negotiation — Integration Notes

Status: implementation complete, **not yet compiled or target-validated** (source tree belongs to the IPC build PC).
Scope: ECDH P-224 key exchange for key negotiation group 2 (IPC LOCALID 3 ↔ EVCU LOCALID 4, CAN HS) per CS.00172, feeding the existing SecOC Profile-2 path.

## 1. What was delivered

### New files (SecurityLib ECC extension)

| File | Role |
|---|---|
| `code/security/include/crypto_lib/seclib_ecc.h` | Public API: init, ephemeral keygen, scalar mult (base/generic), shared secret, X9.63-KDF, wipe |
| `code/security/source/crypto_lib/seclib_ecc.c` | Implementation on mbedtls ECP (2.27.0 port) + fork bignum; RNG via `SecLib_RandomGenerate` |
| `code/security/include/crypto_lib/seclib_ecc_selftest.h` / `source/crypto_lib/seclib_ecc_selftest.c` | KAT self-test: ECDH both directions, 2·G, dA·G, invalid-curve rejection, KDF 16/28/64 B, SHA-256-through-KDF KAT, keygen↔scalar-mult consistency |

### New files (mbedtls core, copied verbatim from reference 2.27.0)

| File | Origin |
|---|---|
| `code/security/include/mbedtls/ecp.h` | reference `include/mbedtls/ecp.h` |
| `code/security/include/mbedtls/ecp_internal.h` | reference `include/mbedtls/ecp_internal.h` |
| `code/security/include/mbedtls/threading.h` | reference (needed by ecp.c include chain) |
| `code/security/source/mbedtls/ecp.c` | reference `library/ecp.c` (0 source edits) |
| `code/security/source/mbedtls/ecp_curves.c` | reference `library/ecp_curves.c` (0 source edits) |
| `code/security/source/mbedtls/ecp_invasive.h` | reference (empty without `MBEDTLS_TEST_HOOKS`) |
| `code/security/source/mbedtls/common.h` | reference (defines `MBEDTLS_STATIC_TESTABLE`) |

### Modified files (fork)

| File | Change |
|---|---|
| `include/mbedtls/config.h` | enabled `MBEDTLS_ECP_C`, `MBEDTLS_ECP_DP_SECP224R1_ENABLED`, `MBEDTLS_ECP_NO_INTERNAL_RNG`; `ECP_MAX_BITS=224`, `ECP_WINDOW_SIZE=3`, `ECP_FIXED_POINT_OPTIM=0` |
| `include/mbedtls/bignum.h` | added `mbedtls_mpi_random()` declaration (upstream 2.27.0 API, required by `ecp.c`) |
| `source/mbedtls/bignum.c` | added `mbedtls_mpi_random()` + local helper `mpi_random_fill_same_limbs()` (upstream logic adapted to fork internals; upstream's `mpi_fill_random_internal`/`mbedtls_mpi_resize_clear` do not exist in the fork) |
| `include/mbedtls/bn_mul.h` | added `MBEDTLS_BYTES_TO_T_UINT_2/4/8` macro block (upstream 2.27.0 verbatim; required by `ecp_curves.c` curve constants) |

### Modified files (Vector component)

| File | Change |
|---|---|
| `component/Crypto_30_CryWrapper/Implementation/Crypto_30_CryWrapper_Hw.c` | includes (`KeyManagement.h`, `seclib_ecc.h`, `<string.h>`); the three `E_NOT_OK` ECC stubs replaced with real implementations (see §3) |

Nothing else in the Vector stack was touched: `vKeyM_MPKA`, `Csm`, `CryIf`, `SecOC`, `Cry_30_Rh850Icus` are unmodified.

## 2. Build integration (GHS project)

Add to the SecurityLib build unit (same place `crypto_library.c`, `secoc_securitylib_csm_wrapper.c` are built):

```
source/crypto_lib/seclib_ecc.c
source/crypto_lib/seclib_ecc_selftest.c
source/mbedtls/ecp.c
source/mbedtls/ecp_curves.c
```

Include paths are unchanged (the mbedtls sources include `"mbedtls/..."`, resolved by the existing `include/` path).

`SecLib_EccInit()` must be called once after `SecLib_Init()` and after the generated Csm random service is available (the RNG bridge uses the Csm random path). Recommended: same init site that currently calls `SecLib_Init()`.

## 3. Provider implementation notes (CryWrapper Hw layer)

The stubs were filled following the third-party-workflow contract of vKeyM_MPKA TR 4.02.00 §5.4–5.6 and the Vector key-element semantics:

- **`Hw_KeyExchangeCalcPubVal`**: generates the ephemeral scalar inside the provider (`SecLib_EccGenerateEphemeralKey`), writes public value as uncompressed `X||Y` (56 B, big endian) into the caller buffer, sets `*publicValueLengthPtr = 56`, and stores the private scalar into element `CRYPTO_KE_KEYEXCHANGE_PRIVKEY` (ID 9) via `KeyElementSetInternal`. MPKA itself never generates `d`; it only zeroizes the element after the negotiation (`CryptoStateMachine.c:1361`). This split matches MPKA's separate `CalcPubVal` / `CalcSecret` calls.
- **`Hw_KeyExchangeCalcSecret`**: reads PRIVKEY (via `Local_KeyElementGet`, which enforces element validity), validates the peer point on-curve (invalid-curve protection), computes `K = d·Q_peer`, and stores the result into `CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE` (element ID 1) honoring its **configured** length: 28 → x only, 56 → x‖y (TR §5.6, Table 5.3).
- **`Hw_KeyDerive`**: reads PASSWORD (element 1 of the KDF-input key, copied there by MPKA from SHAREDVALUE) and SALT (element 13; 1-byte msgGrpId for SecOC, 2-byte prefix+ID for MacSec), runs ANSI X9.63-KDF/SHA-256, writes target key element 1 with the target element's configured length (16 B message-group key per `VKEYM_MPKA_MSGGRP_KEY_SIZE`).

Validity-flag semantics relied upon (verified in `Crypto_30_CryWrapper_KeyManagement.c`): `Csm_KeySetValid` → `KeyValidSet` → `SetKeyState` sets the VALID bit on **all** elements of the key; MPKA pairs every element write/copy with `KeySetValid` (CryptoStateMachine.c:604, 766, 820, 877, 909, 915, 1008, 1060, 1086). Therefore the elements read by the Hw functions are valid by the time they are read, independent of the success/failure validity quirk below.

### Known delivery quirk (do not "fix" ad hoc)

`Local_KeyElementSet` and `Local_KeyElementCopy` in this delivery call `SetKeyElementStateByMask(..., VALID_MASK)` when `retVal != E_OK` — inverted relative to Vector's released semantics (valid-on-success). Because MPKA always follows element writes with `KeySetValid` on the whole key, the practical behavior is correct for the MPKA flow, but this should be confirmed against a pristine Crypto_30_CryWrapper 2.4.0 source during a future code review.

## 4. DaVinci / ECUC configuration checklist (regeneration)

User confirmed the generated configuration can be extended. Per key negotiation group (group 2):

1. **Key `CddKeyNegotiationGroupKeyRef`** (key type template `KeyExchange_NISTP224R1_BD` regardless of curve, TR §5.4): elements with lengths — `OWNPUBKEY` 56, `PRIVKEY` 28, `PARTNER_PUB_KEY` 56, `PARTNER_PUB_KEY_2` 56, `INTERMEDIATE` 56, `SHAREDVALUE` **56** (x‖y per CS.00172 REQ 5.7.2 for message-group keys; use 28 only if a CS revision analysis demands x-only), `KEYEXCHANGE_ALGORITHM` 1, plus `CUSTOM_KEYEXCHANGE_NUM_ECU` 1 and `CUSTOM_KEYEXCHANGE_ECU_ID` 1. All with write access.
2. **`CddKeyNegotiationSharedValueLengthType`** for the group: set consistent with the SHAREDVALUE length choice.
3. **`CddMsgGrpKDFInputKey`**: `KEYDERIVATION_PASSWORD` length == SHAREDVALUE length (TR §5.6); `KEYDERIVATION_SALT` 1 byte (SecOC use case; 2 bytes only if MacSec groups are configured).
4. **`CddMsgGrpTmpKey` / `CddMsgGrpKey`**: element 1 length 16 (message-group key).
5. Curve in vKeyM_MPKA configuration: `VKEYM_MPKA_CURVEID_SECP224` (matches CS.00172 default FIPS P-224).
6. The user's planned "3 additional key elements up to 64 bytes" per key: sizes for P-224 must be 28/56 as above — 64-byte elements are for P-256; configure exact lengths, not a uniform 64.

## 5. Validation plan (build PC / target)

1. **Compile** on the build PC (GHS). No compiler available on this analysis machine — first compile is the gating step. Expect possible strict-prototype/MISRA warnings in the copied 2.27.0 sources; do not reformat, configure exceptions for the mbedtls unit if the project has a different warning policy (existing fork code compiles under the same policy).
2. **Self-test**: call `SecLib_EccSelfTest(NULL)` (or with a status pointer) in a bench build after `SecLib_Init()` + `SecLib_EccInit()`. All 12 KATs must pass. The test exercises: hash core + counter order, KDF lengths 16/28/64, parameter rejection, `2·G`, `dA·G`, generic scalar mult, ECDH in both directions, invalid-curve rejection, and 4× keygen↔scalar-mult consistency (RNG-dependent).
3. **Cross-check** (recommended): independently recompute the baked vectors with Python/OpenSSL on the build PC (`python -c` snippet kept in this repo history; vectors regenerate with any standard EC library).
4. **Timing**: measure `SecLib_EccGenerateEphemeralKey` and `SecLib_EccComputeSharedSecret` on target. CS.00172 REQ 5.8.4 requires < 1.5 s per scalar multiplication. With window size 3 and MPI_WINDOW_SIZE 1 on the RH850 core, expect roughly 30–80 M modular ops equivalents; if the budget is missed, first raise `MBEDTLS_MPI_WINDOW_SIZE` (RAM cost: window table), then `MBEDTLS_ECP_WINDOW_SIZE`.
5. **Memory**: peak heap usage occurs during `mbedtls_ecp_group_load` + one `ecp_mul` (window table 8 points × 2 MPIs × 28 B ≈ 1.4 KB + MPI temporaries). Verify the existing calloc/free backend (plain libc heap in this fork) has that headroom at negotiation time.
6. **End-to-end bench** (once EVCU side is available): run the real $2002-triggered negotiation on CAN HS and verify both ECUs derive the same 16-byte message-group key, then confirm SecOC frames authenticate with the committed key through the existing `SecOcSecurityLib` adapter.

## 6. Assurance boundaries (record in the cybersecurity workproduct)

- Private negotiation keys are generated in **software** (fork bignum + ECP) with ICUS PRNG randomness (`SecLib_RandomGenerate`); ICUS has no ECC engine and no protected slot is used. This is the software interpretation of CS.00172 REQ 5.6.1 ("generate and store within the HPSE"): keys exist only in RAM, are zeroized on every exit path, are never written to NVM, and are erased after use per REQ 5.8.5/5.8.6. Any claim of HPSE protection must be **not** made for this path.
- Entropy quality depends on the ICUS PRNG; CS.00098 compliance for the randomness source must be confirmed by the security team (the delivery's ICUS TR documents PRNG, not TRNG).
- ECDH peer points are validated on-curve before use (invalid-curve hardening), and scalars are generated unbiased ([1, n−1], RFC 6979 §3.3 style).
- Coordinate blinding (`ecp_randomize_jac`) is active because the SecLib layer always passes a non-NULL RNG to `mbedtls_ecp_mul`.

## 7. Open items

1. CS.00172 REQ 5.7.2 step 1 as extracted from the PDF ("bitsize(K) + bitsize(SharedInfo) + 4 octets < hashmaxlen") is mathematically unsatisfiable for P-224 (56-byte Z vs 32-byte hash) and contradicts the standard's own default curve choice — treat as a PDF transcription artifact of the ANSI X9.63 constraint; the implemented KDF follows canonical X9.63. Confirm with the spec owner if the interpretation matters for certification.
2. Confirm the exact F1KM part / ICUS variant against the user manual before release (assurance documentation).
3. Host-side `SecLib_EccWipeState()` call placement: recommend calling it after MPKA finalization callback reports success or failure for all groups (e.g. from `vKeyM_MPKA_KeyNegotiationFinalized` handling), to release the curve tables between negotiations.
4. Phase 2 (out of scope here): wire `vKeyM_MPKA_KeyNegotiationFinalized` → `SecOcSecurityLib_ActivateMessageGroupKey` → ICUS KEY_RAM, and the Dsm/DTC wiring for the MPKA events listed in TR §3.10.
