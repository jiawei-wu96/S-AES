# S-AES implementation in Python

# S-Box for substitution
S_BOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
]

# Inverse S-Box for decryption
INV_S_BOX = [
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE
]

POLY_X1 = 0b0010 #0x2,  x
POLY_X3X0 = 0b1001 #0x9, x^3 + 1
# Round constant for key expansion
ROUND_CONSTANT = [0b1000, 0b0011]

# Multiplication in GF(2^4) with irreducible polynomial x^4 + x + 1
def gf_multiply(a, b):
    product = 0
    for _ in range(4):
        if b & 1:
            product ^= a
        a <<= 1
        if a & 0x10:
            a ^= 0x13  # XOR with irreducible polynomial x^4 + x + 1 (0x13)
        b >>= 1
    return product & 0xF  

def split_to_nibbles(num,nib_num):
    '''
    split a int to a list of nibbles
    num: int to be splitted
    nib_num: how many nibbles do you want?
    (The function itself cannot decide this number because possible extra 0 before highest digit)
    '''
    return [(num >> (4 * i)) & 0xF for i in range(nib_num-1, -1, -1)]

def nibbles_to_int(state):
    i = len(state)-1
    r=0
    for nib in state:
        r = r | ( nib << 4*i )
        i = i-1
    return r
# Substitution using S-Box
def substitute_nibbles(state, s_box):
    return [s_box[i] for i in state]

# Key expansion
def expand_key(key):
    """
    input: key, a list of 4 nibbles
    output = [r[0],r[1],r[2]]
    r[i] is a list of same length with state
    """
    def g_fun(w_in,round): # g function
        '''
        input: w_in, a list containing two nibbles
        round, the current round of key expansion
        '''
        ws= substitute_nibbles(w_in,S_BOX)
        return [ws[1] ^ ROUND_CONSTANT[round],  ws[0]]
        
    w = [0] * 6
    w[0] = key[0:2]
    w[1] = key[2:4]
    r = []
    r.append(key)
    for i in range(2, 6):
        temp = w[i - 1]
        if i % 2 == 0: # in even rounds
            temp = g_fun(temp,i//2-1)
        w[i] = [x ^ y for x,y in zip(w[i - 2], temp) ] # in odd rounds
        if i % 2 ==1: 
            r.append(w[i-1] + w[i])
    return r

# Add round key
def add_round_key(state, round_key):
    """
    input: 
    state, a list containing 4 nibbles
    round_key, a list containing 2 words
    """
    return [i ^j for i,j in zip(state, round_key)]

# Shift rows
def shift_rows(state):
    # state 16 bits
    return [state[0],state[3],state[2],state[1]]

# Mix columns
def mix_columns(state):
    s0_new = gf_multiply(state[0], 0x1) ^ gf_multiply(state[1], 0x4)
    s1_new = gf_multiply(state[0], 0x4) ^ gf_multiply(state[1], 0x1)

    s2_new = gf_multiply(state[2], 0x1) ^ gf_multiply(state[3],0x4)
    s3_new = gf_multiply(state[2], 0x4) ^ gf_multiply(state[3],0x1)
    return [s0_new, s1_new, s2_new, s3_new]

# Inverse mix columns
def inv_mix_columns(state):
    s0_new = gf_multiply(state[0], POLY_X3X0) ^ gf_multiply(state[1], POLY_X1)
    s1_new = gf_multiply(state[0], POLY_X1) ^ gf_multiply(state[1], POLY_X3X0)

    s2_new = gf_multiply(state[2], POLY_X3X0) ^ gf_multiply(state[3], POLY_X1)
    s3_new = gf_multiply(state[2], POLY_X1) ^ gf_multiply(state[3], POLY_X3X0)
    return [s0_new,s1_new,s2_new,s3_new]

# Encrypt a 16-bit block
def encrypt(plaintext, key):
    keys = expand_key(split_to_nibbles(key,4))
    state = split_to_nibbles(plaintext,4) # split to nibbles

    # Initial round key addition
    state = add_round_key(state, keys[0])

    # Main rounds
    for i in range(1, 3):
        state = substitute_nibbles(state, S_BOX)
        state = shift_rows(state)
        if i == 1:
            state = mix_columns(state)
        state = add_round_key(state, keys[i])

    return nibbles_to_int(state)

# Decrypt a 16-bit block
def decrypt(ciphertext, key):
    keys = expand_key(split_to_nibbles(key,4))
    state = split_to_nibbles(ciphertext,4)

    # Final round key addition
    # state = add_round_key(state, keys[2])

    # Main rounds
    for i in range(2, 0, -1):
        state = add_round_key(state, keys[i])
        if i == 1:
            state = inv_mix_columns(state)
        state = shift_rows(state)
        state = substitute_nibbles(state, INV_S_BOX)
    # Initial round key addition
    state = add_round_key(state, keys[0])

    return nibbles_to_int(state)

# Example usage
if __name__ == "__main__":
    plaintext = 0x1234  # 16-bit plaintext
    key = 0x5678        # 16-bit key

    ciphertext = encrypt(plaintext, key)
    print(f"Ciphertext: {hex(ciphertext)}")

    decrypted_text = decrypt(ciphertext, key)
    print(f"Decrypted text: {hex(decrypted_text)}")