# Vehicle Proxi Variant Dataset — Write-Once Protected Storage (Design)

Status: **Draft — for review. Documentation only; nothing implemented yet.**

Scope: one NvM-backed protected dataset holding **vehicle proxi variant data**
(the variant/configuration identity of this vehicle). Unlike the odometer
dataset (10 rotating slots, monotonically advancing counter), this dataset:

- uses **a single NvM block**,
- is **written once** (at EOL / commissioning) and **never rewritten** in the field,
- holds a value that **does not advance** — it is an identity, not a counter,
- is **readable by multiple tasks/consumers** at any time,
- must be **tamper-evident**: any modification of the stored value must be detected.

Working name for the block: **VPD** (Vehicle Proxi Data). Rename freely; all
IDs below are placeholders built on that stem.

---

## 1. Requirements

| ID | Requirement |
|----|-------------|
| R1 | Exactly one NvM block (no slot rotation like `ODOM_01..10`) |
| R2 | Write-once: after a successful commitment, every further write attempt is refused |
| R3 | Multi-consumer reads (application tasks; potentially vKeyM_MPKA proxi logic) |
| R4 | Tamper-evident storage: AES-CMAC integrity over the whole logical block |
| R5 | Consumers never see unverified data (reads are status-gated) |
| R6 | Writes only through a single authenticated provisioning path (EOL/diagnostic) |

## 2. Existing infrastructure being reused (map)

The odometer pattern already provides everything needed; nothing new is
invented below, we only re-wire it for one block and add write-once enforcement.

| Mechanism | Location | Reuse |
|-----------|----------|-------|
| NvM PreWriteTransformation hook (computes CMAC, appends after payload) | `code/security/source/hta_storage/nvm_driver.c:477` (`SecLib_NVM_MACVerify_Write`) | add a case for the VPD block |
| NvM PostReadTransformation hook (recomputes CMAC, mismatch → `NVM_REQ_NOT_OK` → NvM reports `INTEGRITY_FAILED`) | `nvm_driver.c:596` (`SecLib_NVM_MACVerify_Read`) | add a case for the VPD block |
| RAM mirror + status entry `t_sec_nvm_block {ram_block, nvm_status}` | `nvm_driver.c:29-49`, resolved via `Get_MirrorPointer()` at `nvm_driver.c:267` | add `buf_vpd` + `nvm_vpd_block` + switch case |
| Protected RAM section for mirrors | `#pragma ghs section sbss = ".rambufsecurity"` at `nvm_driver.c:12-18` | `buf_vpd` goes there |
| CMAC primitive over ICUS hardware | `SecLib_MACGenerate` / `SecLib_MACVerify` (`code/security/source/crypto_lib/crypto_library.c:222/302`) | unchanged |
| Datastore key | `DATASTORE_KEY` = `KEY_3` (`crypto_library_type.h:226`), or `KEY_RAM` when `KEYRAM_AS_KEY` | reused (see Q2 for the alternative) |
| MAC layout convention | ODOM blocks: **MAC after payload** (`nvm_driver.c:503-505`); `hsto_ReadSecure/WriteSecure` path: MAC first, fixed 64-byte layout (`data_protection.c:48/120`) | follow the ODOM (NvM-hook) layout so the shared hook code path applies |
| Startup verification pattern | `SecSB_VerifyODO()` (`code/security/source/secure_boot/secure_boot.c:536`) reads each block via `NvM_Read` and counts failures | model `SecSB_VerifyVPD()` on it |
| Status enum family | `E_VC_SECBOOT_NVM_*` values (`READ`, `WRITE`, `*_PENDING`, `INTEGRITY`, `READ_ODO`, `WRITE_ODO`, …) | add VPD codes |
| DLT logging with per-file ID ranges | `nvm_driver.c:57` documents its range (comment is stale — file actually uses 20251–20278) | request a fresh range, fix the stale comment |

## 3. Design decisions

**D1 — Single block, no rotation.** The odometer rotates 10 slots because its
value advances and replay must push it *forward*. VPD's value never advances;
there is nothing to gain from rotation, so one block is correct. Redundancy
against media wear/failure is a configuration concern (enable NvM block
redundancy / duplicate handling in the DaVinci NvM configuration for this
block) — not a software rotation concern. Documented trade-off: unlike the
FLS master/backup path in `hsto_ReadSecure` (`data_protection.c:30-34`), a
single NvM block relies on the NvM/Fee layer for redundancy.

**D2 — Three enforcement layers.**
1. *Integrity*: AES-CMAC with `DATASTORE_KEY` over payload + state byte
   (detection — any modification is caught on read).
2. *Write-once (software)*: AUTOSAR NvM per-block write protection
   (`NvM_SetBlockProtection(blockId, TRUE)` with `NvMBlockUseWriteProtection`
   configured) — latched **after** a successful write + read-back verification.
   Availability in this project's NvM version must be confirmed (Q3).
3. *Write-once (hardware, optional hardening)*: provision a dedicated ICUS/SHE
   key slot for VPD and set its write-protect `KEY_FLAG` (the write-protect
   mechanism is already exercised by this codebase — see
   `E_VC_SECBOOT_ICUS_KEY_WRITE_PROTECTED` in `secure_boot.c:142`). After that
   the stored MAC cannot be re-signed even by the ECU itself.

**D3 — State byte inside the MAC'd region.** Layout carries a 1-byte state
(0xFF = erased/pre-provisioned, 0x5A = committed) covered by the CMAC. A torn
write (power loss mid-write) always breaks the MAC and reads back as
*invalid*, never as a half-committed value. Recovery from "invalid" reopens
the block for a legitimate re-provisioning write only (R6 channel); the
protection latch is only set after a *verified* write, so a torn write never
ends up locked.

**D4 — Reads from the startup-verified mirror, not per-read CMAC.** The value
is immutable after commitment, so re-verifying on every read wastes ICUS time.
`SecSB_VerifyVPD()` verifies once at startup; consumers then read the RAM
mirror through the API, which only serves data after verification succeeded
(R5). Per-read CMAC would only be needed if reads bypassed the mirror.

**D5 — Fail policy differs from the odometer deliberately.** `SecSB_VerifyODO`
failure contributes to the secure-boot status. VPD corruption is a data
problem, not a firmware-integrity event: the recommended policy is to raise
`E_VC_SECBOOT_NVM_INTEGRITY_VPD` and **deny dependent features** (e.g. any
variant-dependent behaviour, including MPKA keygroup participation that relies
on proxi data) without failing the boot. Needs product-security confirmation (Q4).

## 4. Block layout (NvM-hook path, custom size)

```
byte offset 0 .. N-1        : payload — vehicle proxi variant data (format TBD, Q1)
byte offset N               : state byte   — 0xFF erased | 0x5A committed
byte offset N+1 .. N+16     : AES-CMAC-16 (DATASTORE_KEY) over bytes 0..N
total: NVM_VPD_BLOCK_SIZE = N + 1 + MAC_BYTE_SIZE   (MAC_BYTE_SIZE = 16, crypto_library_type.h:55)
```

MAC after payload, matching the ODOM hook cases (`nvm_driver.c:492-507`).

## 5. Integration steps (touchpoints, not yet implemented)

1. **`code/security/include/crypto_lib/crypto_library.h`** — add
   `NVM_VPD_BLOCK_SIZE` next to the existing block sizes (lines 51–56).
2. **NvM / DaVinci configuration** (generated, outside this snapshot) — new
   block descriptor `NvMConf_NvMBlockDescriptor_VPD`: built-in CRC **off**
   (CMAC replaces it), `PreWriteTransformation = SecLib_NVM_MACVerify_Write`,
   `PostReadTransformation = SecLib_NVM_MACVerify_Read`, write-protection
   support enabled, redundancy per project policy, and **not** part of the
   security ReadAll group (it is read explicitly at startup, like the ODOM
   blocks — see the ReadAll-skip note at `nvm_driver.c:76-78`).
3. **`nvm_driver.c`**:
   - `buf_vpd[NVM_VPD_BLOCK_SIZE]` in the `.rambufsecurity` section (both
     `__APPLICATION__` branches, lines 12–25);
   - `static t_sec_nvm_block nvm_vpd_block = {buf_vpd, E_VC_SECBOOT_NVM_READ};`
     (pattern at lines 29–43);
   - `case NvMConf_NvMBlockDescriptor_VPD:` in `Get_MirrorPointer()` (line 267),
     in `SecLib_NVM_MACVerify_Write` (pattern at lines 492–507:
     `data_len = Length - MAC_BYTE_SIZE; p_dest = p_source + data_len;`), and
     in `SecLib_NVM_MACVerify_Read` (pattern at lines 610–625);
   - CLI-build `NvM_Write` needs no special case: VPD uses the internal
     `buf_vpd` mirror, unlike the ODOM blocks which pass an external buffer
     (`p_ram_buf = NULL` at lines 342–345) — see Q6;
   - new DLT ID range + fix the stale range comment (line 57).
4. **New access API** (proposal: `vpd_protection.c/h` beside `data_protection.c`):
   - `VPD_Write(value, len)` — provisioning entry: refuse if already committed
     (state byte), assemble payload + state, `NvM_Write(VPD)`, read back +
     verify, then latch `NvM_SetBlockProtection(VPD, TRUE)`;
   - `VPD_Read(out, len)` — consumers: succeeds only when the startup
     verification passed and the block is committed; otherwise error +
     zeroed buffer;
   - `VPD_IsAvailable()` / status query for lifecycle logic.
   Single-caller invariant for the write path documented in the header (R6).
5. **`secure_boot.c`** — `SecSB_VerifyVPD()` modelled on `SecSB_VerifyODO()`
   (lines 536–572): explicit `NvM_Read` of the VPD block; three outcomes —
   erased (OK, unprovisioned), valid (mark available), invalid (integrity
   status). Hook into the security lifecycle after the existing block checks.
6. **Status enum** — add `E_VC_SECBOOT_NVM_READ_VPD`, `E_VC_SECBOOT_NVM_WRITE_VPD`,
   `E_VC_SECBOOT_NVM_INTEGRITY_VPD` next to the ODO equivalents (enum lives in
   the secure-boot status headers, generated/outside this snapshot).
7. **Consumers** — application variant logic reads via `VPD_Read()`.
   Candidate security consumer to confirm: the vKeyM_MPKA proxi callouts
   (`vKeyM_MPKA_IsProxiConfigPresent` / `vKeyM_MPKA_IsEcuPresentInProxi`,
   per `TechnicalReference_vKeyM_MPKA.pdf` ch 4.3) — relationship between this
   vehicle-level proxi data and MPKA keygroup participation must be confirmed
   with the MPKA configuration owner (Q7). Reads before commitment return
   "not available" defaults.
8. **Provisioning path** — recommend an authenticated UDS write (DID conventions
   per `CS_00102` in `standards/`), gated by the required security access level
   and preconditions; alternative is a commissioning routine in the security
   state machine. Whichever is chosen, it is the *only* caller of `VPD_Write` (Q5).
9. **Tests** — state machine (erase → commit → refuse), tamper (bit flips in
   payload, state byte, MAC → read fails), torn write (power loss → invalid,
   re-provisioning possible), protection latch (write refused after latch even
   via `NvM_WriteBlock`), multi-task reads during and after commitment.

## 6. Security boundary — what this does and does not give

- **Tamper-evidence: yes.** Any flash edit (on-target or off-board re-flash of
  the block) breaks the CMAC; reads return an integrity failure and the data
  is never served.
- **Write-once vs. normal software: yes** after the protection latch (layer 2).
- **Write-once vs. a holder of the MAC key: only with layer 3.** CMAC alone
  cannot stop someone with `DATASTORE_KEY` from re-signing modified data. If
  the threat model includes a compromised-but-authenticated ECU, adopt the
  dedicated write-protected key slot (D2 layer 3) — this is the honest
  boundary of the odometer-style protection and the reason the odometer
  relies on slot rotation instead.
- **Confidentiality: no.** CMAC is integrity-only; a flash dump can read the
  variant data. Add encryption only if a requirement appears.
- **Debug/JTAG access** is governed by the existing JTAG-disable flow (JTAG
  block/key already exist in the configuration) — out of scope here.

## 7. Open questions (to settle before implementation)

| # | Question |
|---|----------|
| Q1 | Exact payload content, size, and format of the proxi variant data |
| Q2 | Shared `DATASTORE_KEY` vs. dedicated write-protected SHE key slot (decides layer 3) |
| Q3 | Is NvM per-block write protection (`NvMBlockUseWriteProtection`) available/used in this project's NvM version? |
| Q4 | Fail policy: feature-deny only, or also contribute to boot status? |
| Q5 | Provisioning owner and UDS DID allocation |
| Q6 | Mirror ownership: internal `buf_vpd` (recommended) vs. external struct like `Odsp_OdometerBlockData_t` |
| Q7 | Consumer wiring: does MPKA proxi logic read this dataset? |
| Q8 | Final name (VPD is a placeholder) and DLT ID range |

---

*After implementation, run `graphify update .` (per AGENTS.md) so the knowledge
graph picks up the new nodes and edges.*
