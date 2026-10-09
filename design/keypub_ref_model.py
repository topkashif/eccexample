"""Reference model for CddConcat/CddForward packing (SD.00136/04 Fig.1/Fig.2, MGRP_22/MGRP_21).

Executable spec: the C implementation must produce byte-identical frames.
Run: python keypub_ref_model.py  -> self-test + test vectors printed.
"""

VKEYM_PDU_LEN = 64          # 8-byte vKeyM header + 56-byte P-224 public key
KEY_LEN = 56
NUM_FRAMES = 9
VKEYM_MUX_NEG, VKEYM_MUX_CONF = 0, 7

# (frame mux index, first frame byte, length, key offset)  -- Motorola, byte-aligned
FRAME_MAP = [
    (0, 3, 5, 0),     # Part1 start 56 len 40 -> bytes 3..7
    (1, 1, 7, 5),     # Part2 start 56 len 56 -> bytes 1..7
    (2, 1, 7, 12),
    (3, 1, 7, 19),
    (4, 1, 7, 26),
    (5, 1, 7, 33),
    (6, 1, 7, 40),
    (7, 1, 7, 47),    # Part8
    (8, 1, 2, 54),    # Part9 start 16 len 16 -> bytes 1..2
]
HDR_BYTE = 1  # Key_Header start 16 len 16 -> bytes 1..2 (frame 0)


def vkeym_to_kmsg_hdr(vk):
    """vKeyM header (bytes 0..3) -> SD.00136 16-bit KMSG.HDR."""
    if vk[0] not in (VKEYM_MUX_NEG, VKEYM_MUX_CONF):
        raise ValueError("vKeyM mux id")
    group = (vk[2] << 8) | vk[3]
    if group > 0x3F:
        raise ValueError("group id does not fit GROUPID(6)")
    muxid = 1 if vk[0] == VKEYM_MUX_CONF else 0
    rnd = (vk[1] >> 7) & 1
    ecuid = vk[1] & 0x7F
    return (muxid << 15) | (rnd << 14) | (ecuid << 6) | group


def kmsg_hdr_to_vkeym(hdr):
    muxid, rnd = (hdr >> 15) & 1, (hdr >> 14) & 1
    ecuid, group = (hdr >> 6) & 0xFF, hdr & 0x3F
    if ecuid > 0x7F:
        raise ValueError("ECUID > 127 not representable in vKeyM member id")
    return bytes([VKEYM_MUX_CONF if muxid else VKEYM_MUX_NEG,
                  (rnd << 7) | ecuid, 0x00, group, 0, 0, 0, 0])


def tx_split(pdu):
    """CddConcat Tx: one 64-B vKeyM PDU -> 9 CAN frames."""
    assert len(pdu) == VKEYM_PDU_LEN
    key = pdu[8:]
    hdr = vkeym_to_kmsg_hdr(pdu)
    frames = []
    for mux, fb, ln, ko in FRAME_MAP:
        f = bytearray(8)
        f[0] = mux
        if mux == 0:
            f[HDR_BYTE], f[HDR_BYTE + 1] = hdr >> 8, hdr & 0xFF
        f[fb:fb + ln] = key[ko:ko + ln]
        frames.append(bytes(f))
    return frames


def rx_concat(frames):
    """CddConcat Rx + CddForward Rx: 9 frames (any order) -> 64-B vKeyM PDU."""
    key = bytearray(KEY_LEN)
    mask, hdr = 0, None
    for f in frames:
        mux = f[0]
        if mux >= NUM_FRAMES or mask & (1 << mux):
            continue  # invalid / duplicate
        _, fb, ln, ko = FRAME_MAP[mux]
        key[ko:ko + ln] = f[fb:fb + ln]
        if mux == 0:
            hdr = (f[HDR_BYTE] << 8) | f[HDR_BYTE + 1]
        mask |= 1 << mux
    assert mask == 0x1FF, "incomplete"
    return kmsg_hdr_to_vkeym(hdr) + bytes(key)


if __name__ == "__main__":
    import random
    # Vector 1: IPC (ECUID 3), group 2, negotiation, key = 0x00..0x37
    pdu = bytes([0, 3, 0, 2, 0, 0, 0, 0]) + bytes(range(KEY_LEN))
    fr = tx_split(pdu)
    print("TV1 IPC negotiation, group 2, key=00..37  KMSG.HDR=0x%04X" % vkeym_to_kmsg_hdr(pdu))
    for f in fr:
        print("  0x72  " + " ".join("%02X" % b for b in f))
    # Vector 2: EVCU (ECUID 4) confirmation
    pdu2 = bytes([7, 4, 0, 2, 0, 0, 0, 0]) + bytes(range(0xA0, 0xA0 + KEY_LEN))
    print("TV2 EVCU confirmation KMSG.HDR=0x%04X frame0=%s" %
          (vkeym_to_kmsg_hdr(pdu2), " ".join("%02X" % b for b in tx_split(pdu2)[0])))
    # Self-test: round trip with shuffled order and duplicates
    for _ in range(2000):
        p = bytes([random.choice((0, 7)), (random.randint(0, 1) << 7) | random.randint(1, 127),
                   0, random.randint(0, 63), 0, 0, 0, 0]) + bytes(random.getrandbits(8) for _ in range(KEY_LEN))
        fs = tx_split(p)
        fs = fs + random.sample(fs, 3)
        random.shuffle(fs)
        assert rx_concat(fs) == p
    print("self-test: 2000 random round trips (shuffled + duplicates) OK")
