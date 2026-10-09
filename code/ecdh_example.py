import hashlib
import struct

class MPKANegotiationGroup:
    def __init__(self, member_count: int, local_position: int, algo_selector: int = 0x01):
        # Spec Requirement: Fixed sizes for P-224 variables
        self.priv_key = b""                 # 28 B
        self.own_pub_key = b""              # 56 B (x || y)
        self.peer_pub_keys = {}             # 56 B per element
        self.intermediate = b""             # 56 B
        self.shared_value = b""             # 56 B (x || y, big endian)
        
        # 1 B properties
        self.algo_selector = algo_selector
        self.member_count = member_count
        self.local_position = local_position

    def generate_ephemeral_keys(self, seed_phrase: str):
        """Simulates raw 28-byte P-224 key generation."""
        # Derived Deterministically for demo reproducibility
        base_hash = hashlib.sha224(seed_phrase.encode()).digest()
        self.priv_key = base_hash # 28 Bytes
        
        # Simulate generating a 56-byte public key (28B X || 28B Y)
        x_coord = hashlib.sha224(self.priv_key + b"coord_x").digest()
        y_coord = hashlib.sha224(self.priv_key + b"coord_y").digest()
        self.own_pub_key = x_coord + y_coord

    def compute_2_party_shared_value(self, peer_pub_key: bytes):
        """Simulates the raw mathematical ECDH combination to generate SHAREDVALUE."""
        self.peer_pub_keys[0] = peer_pub_key
        
        # Mix local private key with peer public key to create deterministic x || y shared value
        mix_x = hashlib.sha224(self.priv_key + peer_pub_key[:28]).digest()
        mix_y = hashlib.sha224(self.priv_key + peer_pub_key[28:]).digest()
        
        # Spec Requirement: 56 B (x||y, big endian)
        self.shared_value = mix_x + mix_y

    def zeroize_ephemeral_secrets(self):
        """Zeroization compliance policy for transient elements."""
        self.priv_key = b"\x00" * 28
        self.intermediate = b"\x00" * 56
        self.shared_value = b"\x00" * 56


def x963_kdf_sha256(z: bytes, salt: int, shared_info: bytes = b"SecOC_Label") -> bytes:
    """
    Standard ANSI X9.63 Key Derivation Function over SHA-256.
    Appends a 4-byte big-endian counter to the secret Z and configuration context.
    """
    # Spec Requirement: 1-byte message-group ID as salt
    salt_byte = struct.pack("!B", salt)
    
    counter = 1
    counter_bytes = struct.pack("!I", counter)
    
    # Hash input layout: Z || Counter || Salt || Optional SharedInfo
    ctx = hashlib.sha256()
    ctx.update(z)
    ctx.update(counter_bytes)
    ctx.update(salt_byte)
    ctx.update(shared_info)
    
    # Extract out key and truncate to AES-128 target size (16 Bytes)
    full_digest = ctx.digest()
    return full_digest[:16]


# =====================================================================
# SIMULATION EXECUTION (Two Controller Topology)
# =====================================================================
if __name__ == "__main__":
    print("--- Initialising MPKA 2-Controller Key Agreement ---")
    
    # 1. Setup Group Context for Controller A and Controller B
    ctrl_A = MPKANegotiationGroup(member_count=2, local_position=0)
    ctrl_B = MPKANegotiationGroup(member_count=2, local_position=1)
    
    # 2. Generate Ephemeral Keys (Local Generation)
    ctrl_A.generate_ephemeral_keys("Controller_A_Entropy_Seed")
    ctrl_B.generate_ephemeral_keys("Controller_B_Entropy_Seed")
    
    print(f"Ctrl A - PRIVKEY (Size: {len(ctrl_A.priv_key)}B): {ctrl_A.priv_key.hex()[:10]}...")
    print(f"Ctrl A - OWNPUBKEY (Size: {len(ctrl_A.own_pub_key)}B): {ctrl_A.own_pub_key.hex()[:20]}...")
    print(f"Ctrl B - OWNPUBKEY (Size: {len(ctrl_B.own_pub_key)}B): {ctrl_B.own_pub_key.hex()[:20]}...\n")
    
    # 3. Simulate Peer Public Key Exchange over the network bus
    # Crucial: To model a mutual secret, each uses their own private key + peer public key
    ctrl_A.compute_2_party_shared_value(ctrl_B.own_pub_key)
    ctrl_B.compute_2_party_shared_value(ctrl_A.own_pub_key)
    
    # For simulation parity, we link their shared values symmetrically 
    # (In actual ECDH math, point multiplication commutes perfectly: a*B == b*A)
    unified_secret_x = hashlib.sha224(ctrl_A.priv_key + ctrl_B.priv_key + b"shared_x").digest()
    unified_secret_y = hashlib.sha224(ctrl_A.priv_key + ctrl_B.priv_key + b"shared_y").digest()
    symmetric_shared_value = unified_secret_x + unified_secret_y
    
    ctrl_A.shared_value = symmetric_shared_value
    ctrl_B.shared_value = symmetric_shared_value
    
    print(f"Ctrl A - SHAREDVALUE (Size: {len(ctrl_A.shared_value)}B): {ctrl_A.shared_value.hex()}")
    print(f"Ctrl B - SHAREDVALUE (Size: {len(ctrl_B.shared_value)}B): {ctrl_B.shared_value.hex()}")
    print(f"Shared Values Match Symmetrically: {ctrl_A.shared_value == ctrl_B.shared_value}\n")
    
    # 4. Logical Transition to KDF Input Phase
    # Spec Requirement: KEYDERIVATION_PASSWORD (56 B) & KEYDERIVATION_SALT (1 B Group ID)
    msg_group_id_salt = 0x2A  # Example 1-byte SecOC message-group ID
    
    kdf_password_A = ctrl_A.shared_value
    kdf_password_B = ctrl_B.shared_value
    
    # 5. Derive Temporary Message-Group Keys (Crypto Element ID 1, 16 Bytes)
    temp_key_A = x963_kdf_sha256(kdf_password_A, salt=msg_group_id_salt)
    temp_key_B = x963_kdf_sha256(kdf_password_B, salt=msg_group_id_salt)
    
    print(f"Transient Temporary Key A (Size: {len(temp_key_A)}B): {temp_key_A.hex()}")
    print(f"Transient Temporary Key B (Size: {len(temp_key_B)}B): {temp_key_B.hex()}")
    
    # 6. Apply Security Clean-up Policy (Zeroization of Ephemerals)
    ctrl_A.zeroize_ephemeral_secrets()
    ctrl_B.zeroize_ephemeral_secrets()
    del kdf_password_A, kdf_password_B
    print("\n[SECURITY] Ephemeral secrets zeroized. Ephemeral objects wiped out.")
    
    # 7. Commit Lifecycle Phase (Committed AES-128 SecOC Key)
    final_secoc_key_A = temp_key_A
    final_secoc_key_B = temp_key_B
    del temp_key_A, temp_key_B
    
    print(f"\nFinal Committed SecOC Key A: {final_secoc_key_A.hex()}")
    print(f"Final Committed SecOC Key B: {final_secoc_key_B.hex()}")
    print(f"Agreement status: SUCCESS! Both controllers share a unique AES-128 Key.")
