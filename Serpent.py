import sys

# BITWISE HELPER FUNCTIONS & CONSTANTS
MASK = 0xFFFFFFFF

def rol(x, n):
    """Rotate Left: Shifts bits left, moving overflow bits to the right side."""
    return ((x << n) | (x >> (32 - n))) & MASK

def ror(x, n):
    """Rotate Right: Shifts bits right, moving underflow bits to the left side."""
    return ((x >> n) | (x << (32 - n))) & MASK

def shl(x, n):
    """Shift Left: Shifts bits left, filling the right side with zeros."""
    return (x << n) & MASK


# SERPENT S-BOXES
class SerpentSBoxes:
    """
    Implements the standard 4-bit Serpent S-boxes and dynamically generates
    their inverses. Applies the S-boxes across 32 bit-slices 
    simultaneously to guarantee register alignment and maximize efficiency.
    """
    S = [
        [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
        [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
        [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
        [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
        [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
        [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
        [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
        [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6]
    ]

    INV_S = [[0]*16 for _ in range(8)]
    for i in range(8):
        for j in range(16):
            INV_S[i][S[i][j]] = j

    @staticmethod
    def _apply_sbox(x0, x1, x2, x3, sbox_array):
        y0 = y1 = y2 = y3 = 0
        for i in range(32):
            bit0 = (x0 >> i) & 1
            bit1 = (x1 >> i) & 1
            bit2 = (x2 >> i) & 1
            bit3 = (x3 >> i) & 1
            
            nibble = bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3)
            sub = sbox_array[nibble]
            
            y0 |= (sub & 1) << i
            y1 |= ((sub >> 1) & 1) << i
            y2 |= ((sub >> 2) & 1) << i
            y3 |= ((sub >> 3) & 1) << i
            
        return y0, y1, y2, y3

    @classmethod
    def sbox0(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.S[0])
    @classmethod
    def sbox1(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.S[1])
    @classmethod
    def sbox2(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.S[2])
    @classmethod
    def sbox3(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.S[3])
    @classmethod
    def sbox4(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.S[4])
    @classmethod
    def sbox5(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.S[5])
    @classmethod
    def sbox6(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.S[6])
    @classmethod
    def sbox7(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.S[7])

    @classmethod
    def inv_sbox0(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.INV_S[0])
    @classmethod
    def inv_sbox1(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.INV_S[1])
    @classmethod
    def inv_sbox2(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.INV_S[2])
    @classmethod
    def inv_sbox3(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.INV_S[3])
    @classmethod
    def inv_sbox4(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.INV_S[4])
    @classmethod
    def inv_sbox5(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.INV_S[5])
    @classmethod
    def inv_sbox6(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.INV_S[6])
    @classmethod
    def inv_sbox7(cls, x0, x1, x2, x3): return cls._apply_sbox(x0, x1, x2, x3, cls.INV_S[7])



# SERPENT TRANSFORMATIONS
class SerpentTransform:
    @staticmethod
    def linear_transform(x0, x1, x2, x3):
        """
        The forward linear transformation used during encryption.
        Mixes the four 32-bit registers to achieve maximal avalanche effect.
        """
        x0 = rol(x0, 13)
        x2 = rol(x2, 3)
        x1 = x1 ^ x0 ^ x2
        x3 = x3 ^ x2 ^ shl(x0, 3)
        x1 = rol(x1, 1)
        x3 = rol(x3, 7)
        x0 = x0 ^ x1 ^ x3
        x2 = x2 ^ x3 ^ shl(x1, 7)
        x0 = rol(x0, 5)
        x2 = rol(x2, 22)

        return x0, x1, x2, x3

    @staticmethod
    def inverse_linear_transform(x0, x1, x2, x3):
        """
        The reverse linear transformation used during decryption.
        Strictly reverses the operations of the forward transform from bottom to top.
        """
        x2 = ror(x2, 22)
        x0 = ror(x0, 5)
        x2 = x2 ^ x3 ^ shl(x1, 7)
        x0 = x0 ^ x1 ^ x3
        x3 = ror(x3, 7)
        x1 = ror(x1, 1)
        x3 = x3 ^ x2 ^ shl(x0, 3)
        x1 = x1 ^ x0 ^ x2
        x2 = ror(x2, 3)
        x0 = ror(x0, 13)

        return x0, x1, x2, x3



# KEY EXPANSION SCHEDULE
class SerpentKeySchedule:
    PHI = 0x9E3779B9        # The fractional part of the golden ratio.

    def __init__(self, user_key_bytes):
        """Initializes the Key Schedule and generates the 33 round keys."""
        self.round_keys = self._expand_key(user_key_bytes)

    def _expand_key(self, key_bytes):
        """
        Pads the user key to 256 bits, applies the affine recurrence, 
        and maps intermediate words through S-boxes to create 33 subkeys.
        """
        # Input Validation
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("Invalid key length. Serpent strictly requires 128, 192, or 256 bits.")
        
        key_pad = bytearray(key_bytes)
        if len(key_pad) < 32:
            key_pad.append(0x01)
            while len(key_pad) < 32:
                key_pad.append(0x00)
                
        w = []
        for i in range(8):
            word = int.from_bytes(key_pad[i*4 : (i+1)*4], byteorder='little')
            w.append(word)
            
        # Generate 132 intermediate words
        for i in range(132):
            val = w[i] ^ w[i+3] ^ w[i+5] ^ w[i+7] ^ self.PHI ^ i
            w.append(rol(val, 11))
        
        # S-Box Application (Serpent requires 33 round keys)
        round_keys = []
        for i in range(33):
            k0 = w[8 + i*4]
            k1 = w[8 + i*4 + 1]
            k2 = w[8 + i*4 + 2]
            k3 = w[8 + i*4 + 3]
            sbox_idx = (3 - i) % 8
            sbox_func = getattr(SerpentSBoxes, f"sbox{sbox_idx}")
            rk0, rk1, rk2, rk3 = sbox_func(k0, k1, k2, k3)
            round_keys.append((rk0, rk1, rk2, rk3))
            
        return round_keys



# CORE CIPHER CLASS
class SerpentCipher:
    def __init__(self, key_bytes):
        """Initializes the cipher with the user's key, triggering the key schedule."""
        self.key_schedule = SerpentKeySchedule(key_bytes)
        self.round_keys = self.key_schedule.round_keys

    def encrypt_block(self, plaintext_bytes):
        """Encrypts exactly one 128-bit block (16 bytes) of plaintext."""
        if len(plaintext_bytes) != 16:
            raise ValueError("Serpent encrypts strictly in 128-bit (16-byte) blocks.")

        x0 = int.from_bytes(plaintext_bytes[0:4], byteorder='little')
        x1 = int.from_bytes(plaintext_bytes[4:8], byteorder='little')
        x2 = int.from_bytes(plaintext_bytes[8:12], byteorder='little')
        x3 = int.from_bytes(plaintext_bytes[12:16], byteorder='little')

        # The Main 32-Round Loop (Rounds 0 to 30)
        for i in range(31):
            rk0, rk1, rk2, rk3 = self.round_keys[i]
            x0 ^= rk0; x1 ^= rk1; x2 ^= rk2; x3 ^= rk3

            sbox_func = getattr(SerpentSBoxes, f"sbox{i % 8}")
            x0, x1, x2, x3 = sbox_func(x0, x1, x2, x3)

            x0, x1, x2, x3 = SerpentTransform.linear_transform(x0, x1, x2, x3)

        rk0, rk1, rk2, rk3 = self.round_keys[31]
        x0 ^= rk0; x1 ^= rk1; x2 ^= rk2; x3 ^= rk3

        sbox_func = getattr(SerpentSBoxes, "sbox7")
        x0, x1, x2, x3 = sbox_func(x0, x1, x2, x3)

        rk0, rk1, rk2, rk3 = self.round_keys[32]
        x0 ^= rk0; x1 ^= rk1; x2 ^= rk2; x3 ^= rk3

        return (x0.to_bytes(4, byteorder='little') +
                x1.to_bytes(4, byteorder='little') +
                x2.to_bytes(4, byteorder='little') +
                x3.to_bytes(4, byteorder='little'))

    def decrypt_block(self, ciphertext_bytes):
        """Decrypts exactly one 128-bit block (16 bytes) of ciphertext."""
        if len(ciphertext_bytes) != 16:
            raise ValueError("Serpent decrypts strictly in 128-bit (16-byte) blocks.")

        x0 = int.from_bytes(ciphertext_bytes[0:4], byteorder='little')
        x1 = int.from_bytes(ciphertext_bytes[4:8], byteorder='little')
        x2 = int.from_bytes(ciphertext_bytes[8:12], byteorder='little')
        x3 = int.from_bytes(ciphertext_bytes[12:16], byteorder='little')

        rk0, rk1, rk2, rk3 = self.round_keys[32]
        x0 ^= rk0; x1 ^= rk1; x2 ^= rk2; x3 ^= rk3

        inv_sbox_func = getattr(SerpentSBoxes, "inv_sbox7")
        x0, x1, x2, x3 = inv_sbox_func(x0, x1, x2, x3)

        rk0, rk1, rk2, rk3 = self.round_keys[31]
        x0 ^= rk0; x1 ^= rk1; x2 ^= rk2; x3 ^= rk3

        for i in range(30, -1, -1):
            x0, x1, x2, x3 = SerpentTransform.inverse_linear_transform(x0, x1, x2, x3)

            inv_sbox_func = getattr(SerpentSBoxes, f"inv_sbox{i % 8}")
            x0, x1, x2, x3 = inv_sbox_func(x0, x1, x2, x3)

            rk0, rk1, rk2, rk3 = self.round_keys[i]
            x0 ^= rk0; x1 ^= rk1; x2 ^= rk2; x3 ^= rk3

        return (x0.to_bytes(4, byteorder='little') +
                x1.to_bytes(4, byteorder='little') +
                x2.to_bytes(4, byteorder='little') +
                x3.to_bytes(4, byteorder='little'))


# INTERACTIVE TERMINAL & PADDING
def pad_data(data_bytes):
    """Applies PKCS#7 padding to make data a multiple of 16 bytes."""
    padding_len = 16 - (len(data_bytes) % 16)
    return data_bytes + bytes([padding_len] * padding_len)

def unpad_data(data_bytes):
    """Removes PKCS#7 padding after decryption."""
    padding_len = data_bytes[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding detected.")
    return data_bytes[:-padding_len]

def main():
    print("Welcome to The Serpent Cipher")
    
    mode = input("Would you like to (E)ncrypt or (D)ecrypt? ").strip().upper()
    if mode not in ['E', 'D']:
        print("Error: Please select 'E' for Encrypt or 'D' for Decrypt.")
        sys.exit(1)

    user_key = input("Enter your secret encryption key: ").encode('utf-8')
    
    if len(user_key) < 32:
        user_key = user_key.ljust(32, b'\0')
    elif len(user_key) > 32:
        user_key = user_key[:32]
    
    try:
        cipher = SerpentCipher(user_key)
    except Exception as e:
        print(f"Initialization Error: {e}")
        sys.exit(1)

    if mode == 'E':
        plaintext = input("Enter the message to encrypt: ").encode('utf-8')
        padded_pt = pad_data(plaintext)
        
        ciphertext = b""
        for i in range(0, len(padded_pt), 16):
            block = padded_pt[i:i+16]
            ciphertext += cipher.encrypt_block(block)
            
        print(f"\n[+] Ciphertext (Hex): {ciphertext.hex()}")

    elif mode == 'D':
        hex_ct = input("Enter the ciphertext (in Hex format): ").strip()
        try:
            ciphertext = bytes.fromhex(hex_ct)
        except ValueError:
            print("Error: Invalid Hex string provided.")
            sys.exit(1)
            
        if len(ciphertext) % 16 != 0:
            print("Error: Ciphertext length must be a multiple of 16 bytes.")
            sys.exit(1)

        decrypted_padded = b""
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_padded += cipher.decrypt_block(block)
            
        try:
            plaintext = unpad_data(decrypted_padded)
            print(f"\n[+] Decrypted Message: {plaintext.decode('utf-8')}")
        except Exception:
            print("\n[-] Error: Decryption failed. Incorrect key or corrupted data.")

if __name__ == "__main__":
    main()