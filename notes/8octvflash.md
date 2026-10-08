I read all five config screenshots and researched the ECDH key-element question against the Vector TR (§5.4–5.7), the MPKA state machine, and the wrapper implementation. Both documents are updated and opened. Here is the direct answer.

## Your instinct is right — and wrong at the same time

**You do not need one element definition per MPKA key.** You need **12 element definitions + 3 key types, and only 4 new `CryptoKey` instances** — because key types are *layouts* that multiple keys reference. The current draft (four element definitions named `CryptoKey_MPKA_G2_Exchange/_KdfInput/_TmpMac/_FinalMac`) splits the layers the wrong way: Exchange and KdfInput each need *several* elements, while TmpMac and FinalMac *share* one element type.

## What the ECDH use case actually requires (source-verified)

**Negotiation key (`CddKeyNegotiationGroupKeyRef`) — 9 elements** (TR §5.4 Tables 5.1/5.2 + §5.4.1 third-party caution):

| Element | ID (`CRYPTO_KE_*`) | Size P-224 | Written by |
|---|---|---|---|
| PRIVKEY | 9 | 28 B | wrapper (fresh scalar), MPKA zeroizes (:872/:1361) |
| OWNPUBKEY | 10 | 56 B | wrapper (X‖Y), MPKA zeroizes (:1374) |
| SHAREDVALUE | 1 | **28 or 56 = your D2 encoding** | wrapper, MPKA copies + zeroizes |
| PARTNER_PUB_KEY | delivery-defined | 56 B | MPKA **every round** (:809) — ECDH *and* ECBD |
| PARTNER_PUB_KEY_2 | delivery-defined | 56 B | MPKA (:816) — even for ECDH |
| INTERMEDIATE | delivery-defined | 56 B | MPKA cancel path zeroizes it unconditionally (:1389) |
| ALGORITHM | 12 | 1 B | MPKA at runtime (:761) |
| ECU_ID, NUM_ECU | delivery-defined | 1 B each | MPKA at init (:702, :765) — TR Table 5.2 requires them for any third-party stack |

The ECBD-only elements stay because the cancel path (`vKeyM_MPKA_ProcessCancelCryptoState`) writes them **unconditionally** — deleting them fails cancellation, not just ECBD.

**KDF input key — 2 elements:** PASSWORD (ID 1, length must equal SHAREDVALUE length, TR §5.6) + SALT (ID 13, ≥ 1 B). **Temp + final keys — one shared 16-byte type** (TR §5.7.1). Your `secoc_securitylib_csm_wrapper.c` SecOC path needs exactly these.

## What the screenshots show to fix

1. **Element ID 7 on all four MPKA elements matches no `CRYPTO_KE_*` macro** — that's the GUI's row index (7th–10th entries), not a configured ID. The wrapper searches elements by ID, so a wrong ID = `CRYPTO_E_KEY_NOT_AVAILABLE` at the first MPKA write.
2. **Size 64 is wrong for every role** — KEX elements are 28/56/1, KDF 28-or-56/1, msg key 16. (64 is only right for SECP256 pub/intermediate.)
3. **RA_ALLOWED everywhere is unnecessary** — verified in `Crypto_30_CryWrapper_KeyManagement.c`: only the *public* `Csm_KeyElementGet` enforces read access; `Csm_KeyElementCopy` and the provider's internal ECDH/KDF reads do **not**. Secret elements can stay `RA_DENIED` without breaking MPKA's flows. (Only Option B — KEY_RAM adapter — needs the final key `RA_ALLOWED`.)
4. **No `CryptoKey` instances yet** — the 4 keys, then CryIf keys/channel, then the 4 `CsmKey`s MPKA references, are the remaining chain.
5. Your existing SHE key IDs 0–25 stay untouched — pick non-colliding CryptoKeyIds; element IDs are a separate namespace. And your ICUS-routed AES configs confirm D4: keep two provider objects (CryWrapper for MPKA's ECDH/KDF, ICUS for AES/CMAC), each with its own CryIf channel.

Deliverables refreshed: **[work order §1b](file:///D:/ai/partx_explain/reference/mpka-davinci-work-order.html)** now contains the full draft-vs-required delta table, and **[lesson 0006 §4](file:///D:/ai/partx_explain/lessons/0006-mpka-davinci-csm-cryif-crypto.html)** has the compact comparison — both opened in your browser.