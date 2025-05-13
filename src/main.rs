const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn sub_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        state[i] = SBOX[state[i] as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let mut temp: u8;
    // Row 0 does not change

    // Row 1: Shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2: Shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3: Shift left by 3, which is equivalent to a right shift by 1
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b > 0 {
        if b & 1 == 1 {
            p ^= a;
        }
        let hi_bit_set = a & 0x80;
        a <<= 1;
        if hi_bit_set != 0 {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x^2 + 1
        }
        b >>= 1;
    }
    p
}

fn mix_columns(state: &mut [u8; 16]) {
    let mut temp = [0u8; 16];
    for i in 0..4 {
        let j = i * 4;
        temp[j] = gf_mul(0x02, state[j]) ^ gf_mul(0x03, state[j + 1]) ^ state[j + 2] ^ state[j + 3];
        temp[j + 1] =
            state[j] ^ gf_mul(0x02, state[j + 1]) ^ gf_mul(0x03, state[j + 2]) ^ state[j + 3];
        temp[j + 2] =
            state[j] ^ state[j + 1] ^ gf_mul(0x02, state[j + 2]) ^ gf_mul(0x03, state[j + 3]);
        temp[j + 3] =
            gf_mul(0x03, state[j]) ^ state[j + 1] ^ state[j + 2] ^ gf_mul(0x02, state[j + 3]);
    }
    for i in 0..16 {
        state[i] = temp[i];
    }
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

const R_CONSTANTS: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn key_expansion(key: &[u8; 16]) -> [u8; 176] {
    let mut round_keys = [0u8; 176];

    // Initial key
    round_keys[..16].copy_from_slice(key);

    let mut temp = [0u8; 4];
    let mut i = 16;

    while i < 176 {
        // word i-1
        temp.copy_from_slice(&round_keys[i - 4..i]);
        if i % 16 == 0 {
            // Rotate
            temp.rotate_left(1);
            // SubBytes
            for j in 0..4 {
                temp[j] = SBOX[temp[j] as usize];
            }
            // XOR with RCON
            temp[0] ^= R_CONSTANTS[i / 16 - 1];
        }
        for j in 0..4 {
            round_keys[i] = round_keys[i - 16] ^ temp[j];
            i += 1;
        }
    }

    round_keys
}

fn aes_encrypt_software(input: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut state = *input;
    let round_keys = key_expansion(key);

    add_round_key(&mut state, &round_keys[..16]);

    for round in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &round_keys[round * 16..(round + 1) * 16]);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[160..]);

    state
}

fn aes_encrypt_hardware(input: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut state = *input;
    let round_keys = key_expansion(key);

    add_round_key(&mut state, &round_keys[..16]);

    let mut block = (
        u32::from_le_bytes(state[0..4].try_into().unwrap()),
        u32::from_le_bytes(state[4..8].try_into().unwrap()),
        u32::from_le_bytes(state[8..12].try_into().unwrap()),
        u32::from_le_bytes(state[12..16].try_into().unwrap()),
    );

    for round in 1..10 {
        let rk = &round_keys[round * 16..(round + 1) * 16];
        let mut a0 = u32::from_le_bytes(rk[0..4].try_into().unwrap());
        let mut a1 = u32::from_le_bytes(rk[4..8].try_into().unwrap());
        let mut a2 = u32::from_le_bytes(rk[8..12].try_into().unwrap());
        let mut a3 = u32::from_le_bytes(rk[12..16].try_into().unwrap());

        a0 = aes32esmi(a0, block.0, 0);
        a0 = aes32esmi(a0, block.1, 1);
        a0 = aes32esmi(a0, block.2, 2);
        a0 = aes32esmi(a0, block.3, 3);

        a1 = aes32esmi(a1, block.1, 0);
        a1 = aes32esmi(a1, block.2, 1);
        a1 = aes32esmi(a1, block.3, 2);
        a1 = aes32esmi(a1, block.0, 3);

        a2 = aes32esmi(a2, block.2, 0);
        a2 = aes32esmi(a2, block.3, 1);
        a2 = aes32esmi(a2, block.0, 2);
        a2 = aes32esmi(a2, block.1, 3);

        a3 = aes32esmi(a3, block.3, 0);
        a3 = aes32esmi(a3, block.0, 1);
        a3 = aes32esmi(a3, block.1, 2);
        a3 = aes32esmi(a3, block.2, 3);

        block = (a0, a1, a2, a3);
    }

    let mut state = [0u8; 16];
    state[0..4].copy_from_slice(&block.0.to_le_bytes());
    state[4..8].copy_from_slice(&block.1.to_le_bytes());
    state[8..12].copy_from_slice(&block.2.to_le_bytes());
    state[12..16].copy_from_slice(&block.3.to_le_bytes());

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[160..]);

    state
}

/// rs1: round key state, rs2: plaintext
/// output: round key state
fn aes32esmi(rs1: u32, rs2: u32, bs: u8) -> u32 {
    let shamt = (bs & 0x03) * 8;
    let si = (rs2 >> shamt) & 0xFF;
    let so = SBOX[si as usize];
    let mixed = u32::from_be_bytes([gf_mul(so, 0x03), so, so, gf_mul(so, 0x02)]);
    rs1 ^ mixed.rotate_left(shamt.into())
}

fn main() {
    // Key: cese4040password
    let key: [u8; 16] = [
        0x63, 0x65, 0x73, 0x65, 0x34, 0x30, 0x34, 0x30, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
        0x64,
    ];

    // Plaintext: Hello, World!000
    let plaintext: [u8; 16] = [
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x30, 0x30,
        0x30,
    ];

    let expected_output: [u8; 16] = [
        0x14, 0x09, 0xa5, 0xfb, 0x1f, 0xf4, 0x4b, 0x71, 0xbe, 0xaa, 0x25, 0x2e, 0x0f, 0x08, 0xf9,
        0xaa,
    ];

    let encrypted = aes_encrypt_software(&plaintext, &key);

    assert_eq!(encrypted, expected_output);

    let encrypted = aes_encrypt_hardware(&plaintext, &key);

    assert_eq!(encrypted, expected_output);
}
