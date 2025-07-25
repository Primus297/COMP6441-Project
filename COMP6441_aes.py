# This code is an implementation of the AES block cipher.
# It provides single-block ECB encryption for 128, 192 and 256.
# It also has  official NIST GFSbox test vectors for all three key sizes.
#
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
RCON = [
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a
]

def sub_bytes(state):
    for row_idx in range(len(state)):
        row = state[row_idx]
        for col_idx in range(len(row)):
            byte = row[col_idx]
            row[col_idx] = SBOX[byte]

def shift_rows(state):
    for row_index in range(1, 4):
        shifted = []
        for offset in range(4):
            shifted.append(state[row_index][(offset + row_index) % 4])
        state[row_index] = shifted

def mix_single_column(col):
    a0, a1, a2, a3 = col
    t = a0 ^ a1 ^ a2 ^ a3
    z0 = xtime(a0 ^ a1) ^ a0 ^ t
    z1 = xtime(a1 ^ a2) ^ a1 ^ t
    z2 = xtime(a2 ^ a3) ^ a2 ^ t
    z3 = xtime(a3 ^ a0) ^ a3 ^ t
    return [z0, z1, z2, z3]

def mix_columns(state):
    for col_index in range(4):
        column = []
        for row_index in range(4):
            column.append(state[row_index][col_index])
        mixed = mix_single_column(column)
        for row_index in range(4):
            state[row_index][col_index] = mixed[row_index]

def add_round_key(state, roundkey):
    for r in range(4):
        for c in range(4):
            state[r][c] = state[r][c] ^ roundkey[r][c]

def xtime(byte):
    return ((byte << 1) & 0xFF) ^ (0x1B if byte & 0x80 else 0x00)

def bytes2matrix(block):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]

def matrix2bytes(matrix):
    return bytes(matrix[r][c] for c in range(4) for r in range(4))

def key_expansion(key):
    key_len = len(key)
    if key_len == 16:
        nk, nr = 4, 10
    elif key_len == 24:
        nk, nr = 6, 12
    elif key_len == 32:
        nk, nr = 8, 14
    else:
        raise ValueError("Invalid key length")
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk, 4*(nr+1)):
        temp = w[i-1][:]
        if i % nk == 0:
            temp = [SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= RCON[(i//nk)-1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i-nk][j] ^ temp[j] for j in range(4)])
    # Build round keys as 4x4 byte matrices in state order
    roundkeys = []
    for r in range(nr+1):
        roundkey = [w[4*r + i] for i in range(4)]
        # Transpose so [row][col]
        roundkey = [[roundkey[row][col] for row in range(4)] for col in range(4)]
        roundkeys.append(roundkey)
    return roundkeys, nr

def aes_encrypt_block(plaintext, key):
    assert len(plaintext) == 16
    key_len = len(key)
    roundkeys, nr = key_expansion(key)
    state = bytes2matrix(plaintext)
    add_round_key(state, roundkeys[0])
    for r in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, roundkeys[r])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, roundkeys[nr])
    return matrix2bytes(state)

def test_nist_vectors():
    print("NIST ECB GFSbox Tests for AES-128/192/256")
    vectors = [
        {
            "name": "AES-128",
            "key": "00000000000000000000000000000000",
            "plaintext": "f34481ec3cc627bacd5dc3fb08f273e6",
            "expected": "0336763e966d92595a567cc9ce537f5e"
        },
        {
            "name": "AES-192",
            "key": "000000000000000000000000000000000000000000000000",
            "plaintext": "1b077a6af4b7f98229de786d7516b639",
            "expected": "275cfc0413d8ccb70513c3859b1d0f72"
        },
        {
            "name": "AES-256",
            "key": "0000000000000000000000000000000000000000000000000000000000000000",
            "plaintext": "014730f80ac625fe84f026c60bfd547d",
            "expected": "5c9d844ed46f9885085e5d6a4f94c7d7"
        }
    ]
    all_pass = True
    for v in vectors:
        key = bytes.fromhex(v["key"])
        pt = bytes.fromhex(v["plaintext"])
        expected = v["expected"].lower()
        ct = aes_encrypt_block(pt, key).hex()
        print(f"{v['name']}  Key: {v['key']}  Plain Text: {v['plaintext']}")
        print(f"Expected: {expected}\nGot     : {ct}")
        if ct == expected:
            print("PASSED\n")
        else:
            print("FAILED\n")
            all_pass = False
    if all_pass:
        print("All tests passed\n")
    else:
        print("Tests failed\n")

def example_aes():
    print("Example for AES-128, AES-192, AES-256")
    pt = b'Hello World!!!!!' # plain text must be 16 bytes
    k128 = bytes.fromhex('12345678123456781234567812345678') #AES 128
    k192 = bytes.fromhex('123456781234567812345678123456781234567812345678') #AES 192
    k256 = bytes.fromhex('1234567812345678123456781234567812345678123456781234567812345678') #AES 256
    print("Plaintext:", pt)
    print("AES-128 Ciphertext:", aes_encrypt_block(pt, k128).hex())
    print("AES-192 Ciphertext:", aes_encrypt_block(pt, k192).hex())
    print("AES-256 Ciphertext:", aes_encrypt_block(pt, k256).hex())

if __name__ == "__main__":
    test_nist_vectors()
    example_aes()
