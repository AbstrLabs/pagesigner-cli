# SYMMETRIC CIPHERS
AES_ROUNDS = 10

# AES_SBOX is some permutation of numbers 0-255
AES_SBOX = [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125,
    250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204,
    52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235,
    39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209,
    0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51,
    133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33,
    16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96,
    129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36,
    92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244,
    234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139,
    138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17,
    105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104,
    65, 153, 45, 15, 176, 84, 187, 22
]

def bytes_to_num(b):
    return int.from_bytes(b, "big")

def num_to_bytes(num, bytes_len):
    return int.to_bytes(num, bytes_len, "big")

def xor(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

def multiply_blocks(x, y):
    z = 0
    for i in range(128):
        if x & (1 << (127 - i)):
            z ^= y
        y = (y >> 1) ^ (0xe1 << 120) if y & 1 else y >> 1
    return z

def ghash(h, data):
    CHUNK_LEN = 16

    y = 0
    for pos in range(0, len(data), CHUNK_LEN):
        chunk = bytes_to_num(data[pos: pos + CHUNK_LEN])
        y = multiply_blocks(y ^ chunk, h)
    return y

def calc_pretag(key, encrypted_msg, associated_data):
    v = b"\x00" * (16 * ((len(associated_data) + 15) // 16) - len(associated_data))
    u = b"\x00" * (16 * ((len(encrypted_msg) + 15) // 16) - len(encrypted_msg))

    h = bytes_to_num(aes128_encrypt(key, b"\x00" * 16))
    data = (associated_data + v + encrypted_msg + u +
            num_to_bytes(len(associated_data)*8, 8) + num_to_bytes(len(encrypted_msg)*8, 8))
    return num_to_bytes(ghash(h, data), 16)

def aes128_expand_key(key):
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    enc_keys = [[0, 0, 0, 0] for i in range(AES_ROUNDS + 1)]
    enc_keys[0] = [bytes_to_num(key[i:i + 4]) for i in [0, 4, 8, 12]]

    for t in range(1, AES_ROUNDS + 1):
        prev_key = enc_keys[t-1]
        enc_keys[t][0] = ((AES_SBOX[(prev_key[3] >> 8*2) & 0xFF] << 8*3) ^
                          (AES_SBOX[(prev_key[3] >> 8*1) & 0xFF] << 8*2) ^
                          (AES_SBOX[(prev_key[3] >> 8*0) & 0xFF] << 8*1) ^
                          (AES_SBOX[(prev_key[3] >> 8*3) & 0xFF] << 8*0) ^
                          (RCON[t-1] << 8*3) ^ prev_key[0])

        for i in range(1, 4):
            enc_keys[t][i] = enc_keys[t][i-1] ^ prev_key[i]
    return enc_keys

def aes128_encrypt(key, plaintext):
    TWOTIMES = [2*num if 2*num < 256 else 2*num & 0xff ^ 27 for num in range(256)]

    enc_keys = aes128_expand_key(key)

    t = [bytes_to_num(plaintext[4*i:4*i + 4]) ^ enc_keys[0][i] for i in range(4)]
    for r in range(1, AES_ROUNDS):
        t = [[AES_SBOX[(t[(i + 0) % 4] >> 8*3) & 0xFF],
              AES_SBOX[(t[(i + 1) % 4] >> 8*2) & 0xFF],
              AES_SBOX[(t[(i + 2) % 4] >> 8*1) & 0xFF],
              AES_SBOX[(t[(i + 3) % 4] >> 8*0) & 0xFF]] for i in range(4)]

        t = [[c[1] ^ c[2] ^ c[3] ^ TWOTIMES[c[0] ^ c[1]],
              c[0] ^ c[2] ^ c[3] ^ TWOTIMES[c[1] ^ c[2]],
              c[0] ^ c[1] ^ c[3] ^ TWOTIMES[c[2] ^ c[3]],
              c[0] ^ c[1] ^ c[2] ^ TWOTIMES[c[3] ^ c[0]]] for c in t]

        t = [bytes_to_num(t[i]) ^ enc_keys[r][i] for i in range(4)]

    result = [bytes([
        AES_SBOX[(t[(i + 0) % 4] >> 8*3) & 0xFF] ^ (enc_keys[-1][i] >> 8*3) & 0xFF,
        AES_SBOX[(t[(i + 1) % 4] >> 8*2) & 0xFF] ^ (enc_keys[-1][i] >> 8*2) & 0xFF,
        AES_SBOX[(t[(i + 2) % 4] >> 8*1) & 0xFF] ^ (enc_keys[-1][i] >> 8*1) & 0xFF,
        AES_SBOX[(t[(i + 3) % 4] >> 8*0) & 0xFF] ^ (enc_keys[-1][i] >> 8*0) & 0xFF
    ]) for i in range(4)]
    return b"".join(result)

def aes128_ctr(key, msg, nonce, counter_start_val):
    BLOCK_SIZE = 16

    ans = []
    counter = counter_start_val
    for s in range(0, len(msg), BLOCK_SIZE):
        chunk = msg[s:s+BLOCK_SIZE]
        print('nonce', nonce)
        chunk_nonce = nonce + num_to_bytes(counter, 4)
        print('chunk_nonce', chunk_nonce)
        encrypted_chunk_nonce = aes128_encrypt(key, chunk_nonce)
        print('encrypted_chunk_nonce')
        print(encrypted_chunk_nonce)
        decrypted_chunk = xor(chunk, encrypted_chunk_nonce)
        ans.append(decrypted_chunk)

        counter += 1
    return b"".join(ans)

def aes128_gcm_decrypt(key, msg, nonce, associated_data):
    TAG_LEN = 16

    return aes128_ctr(key, msg, nonce, 2)[:-16]
    # encrypted_msg, tag = msg[:-TAG_LEN], msg[-TAG_LEN:]

    # pretag = calc_pretag(key, encrypted_msg, associated_data)
    # check_tag = aes128_ctr(key, pretag, nonce, counter_start_val=1)
    # if check_tag != tag:
    #     raise ValueError("Decrypt error, bad tag")
    # return aes128_ctr(key, encrypted_msg, nonce, counter_start_val=2)

def aes128_gcm_encrypt(key, msg, nonce, associated_data):
    encrypted_msg = aes128_ctr(key, msg, nonce, counter_start_val=2)

    pretag = calc_pretag(key, encrypted_msg, associated_data)
    tag = aes128_ctr(key, pretag, nonce, counter_start_val=1)
    return encrypted_msg + tag

APPLICATION_DATA = b'\x17'
LEGACY_TLS_VERSION = b'\x03'

# print(aes128_encrypt(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'), bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')).hex())

server_records0 = bytes([
    0, 0, 0, 0, 0, 0, 0, 1, 124, 91, 228, 82, 57, 48, 237, 251, 217, 241, 170, 46, 113, 100, 150, 70, 52, 190, 213, 222, 102, 74, 128, 62, 193, 24, 94, 231, 191, 200, 43, 123, 60, 138, 215, 123, 169, 253, 122, 172, 206, 255, 107, 8, 165, 219, 102, 89, 132, 167, 58, 15, 54, 205, 168, 133, 128, 8, 123, 117, 42, 178, 147, 198, 38, 59, 222, 76, 191, 221, 167, 88, 254, 4, 220, 128, 164, 112, 233, 231, 233, 235, 134, 250, 194, 34, 112, 197, 23, 214, 104, 76, 215, 61, 171, 203, 73, 104, 143, 249, 157, 214, 7, 249, 207, 96, 55, 161, 138, 229, 90, 168, 204, 110, 178, 187, 175, 155, 145, 76, 226, 62, 249, 60, 194, 21, 17, 242, 84, 156, 66, 184, 81, 192, 135, 90, 215, 229, 228, 85, 111, 119, 247, 237, 3, 74, 42, 159, 230, 187, 163, 67, 116, 34, 216, 177, 114, 196, 132, 208, 194, 135, 60, 214, 114, 174, 54, 53, 88, 39, 119, 37, 133, 245, 50, 71, 201, 243, 153, 255, 134, 168, 21, 156, 60, 108, 129, 239, 198, 187, 112, 216, 60, 142, 131, 123, 54, 42, 69, 95, 239, 45, 100, 138, 193, 132, 173, 143, 42, 15, 96, 29, 88, 158, 122, 81, 180, 82, 151, 23, 170, 37, 37, 101, 247, 181, 171, 121, 26, 9, 223, 122, 164, 19, 125, 198, 148, 176, 57, 138, 201, 90, 201, 131, 96, 142, 228, 131, 82, 24, 199, 82, 134, 169, 84, 37, 128, 254, 31, 187, 207, 108, 164, 203, 158, 18, 252, 184, 111, 20, 149, 117, 231, 198, 129, 80, 209, 151, 149, 99, 183, 225, 184, 12, 150, 141, 66, 229, 59, 230, 113, 227, 226, 203, 250, 175, 63, 165, 147, 124, 42, 2, 189, 88, 98, 97, 97, 107, 183, 208, 124, 106, 37, 1, 58, 3, 208, 156, 27, 154, 231, 16, 123, 199, 25, 234, 191, 178, 113, 124, 209, 201, 100, 164, 57, 113, 154, 181, 144, 89, 14, 2, 88, 190, 248, 206, 191, 234, 201, 173, 147, 205, 73, 115, 186, 85, 111, 197, 95, 10, 33, 125, 152, 222, 26, 79, 90, 176, 172, 29, 18, 133, 13, 247, 9, 21, 102, 10, 52, 113, 78, 69, 224, 117, 144, 105, 198, 23, 123, 22, 159, 18, 250, 166, 114, 18, 99, 40, 101, 36, 156, 103, 5, 191, 147, 71, 15, 205, 151, 162, 175, 175, 255, 117, 75, 62, 81, 101, 217, 152, 27, 231, 41, 70, 146, 182, 221, 66, 191, 104, 218, 89, 191, 168, 142, 106, 159, 140, 13, 119, 250, 217, 55, 117, 5, 79, 45, 193, 251, 175, 66, 171, 109, 18, 12, 141, 181, 1, 247, 82, 110, 212, 107, 250, 177, 169, 179, 30, 32, 88, 142, 47, 88, 177, 192, 202, 15, 63, 33, 34, 250, 10, 172, 202, 251, 49, 41, 182, 240, 50, 28, 225, 134, 15, 87, 87, 17, 41, 238, 183, 225, 68, 227, 109, 238, 198, 96, 107, 96, 100, 12, 179, 14, 140, 30, 231, 41, 181, 131, 99, 56, 102, 4, 177, 140, 14, 243, 21, 103, 140, 89, 192, 139, 249, 55, 234, 110, 65, 217, 197, 158, 15, 171, 64, 201, 52, 38, 159, 124, 244, 255, 125, 151, 149, 30, 249, 74, 95, 58, 194, 168, 25, 132, 90, 212, 116, 60, 163, 188, 92, 103, 150, 104, 48, 187, 15, 140, 192, 231, 140, 12, 39, 208, 136, 187, 169, 91, 179, 252, 107, 198, 44, 31, 90, 236, 122, 154, 85, 126, 243, 206, 133, 78, 95, 28, 249, 32, 211, 165, 135, 194, 31, 244, 112, 54, 224, 65, 66, 57, 221, 82, 235, 65, 211, 150, 172, 213, 114, 194, 123, 43, 210, 23, 218, 243, 207, 142, 76, 184, 52, 184, 175, 21, 189, 15, 252, 4, 185, 73, 119, 234, 240, 42, 189, 196, 51, 159, 253, 141, 227, 161, 202, 126, 131, 62, 28, 119, 39, 107, 244, 90, 43, 225, 187, 121, 108, 122, 234, 254, 102, 120, 172, 201, 93, 11, 189, 195, 216, 115, 139, 188, 98, 213, 13, 142, 241, 92, 55, 244, 108, 239, 10, 33, 191, 233, 112, 199, 78, 18, 17, 98, 253, 134, 75, 112, 176, 14, 29, 226, 86, 134, 133, 32, 67, 22, 67, 2, 103, 203, 83, 10, 68, 144, 150, 209, 61, 149, 221, 115, 140, 96, 29, 10, 217, 28, 234, 62, 231, 2, 185, 34, 102, 146, 74, 162, 196, 43, 226, 152, 247, 204, 84, 117, 99, 83, 135, 241, 108, 121, 222, 225, 237, 114, 141, 193, 25, 13, 6, 27, 1, 31, 95, 38, 25, 125, 233, 152, 247, 150, 224, 147, 58, 1, 119, 13, 246, 181, 2, 189, 75, 90, 90, 84, 224, 234, 191, 159, 235, 187, 
])
client_swk_share = bytes([
    57, 101, 95, 125, 91, 138, 4, 49, 4, 253, 141, 213, 206, 26, 159, 92, 
])
notary_swk_share = bytes([
    87, 248, 86, 137, 157, 18, 224, 94, 169, 206, 35, 138, 231, 117, 12, 83,
])
client_siv_share = bytes([167, 161, 91, 147, ])
notary_siv_share = bytes([252, 46, 173, 33, ])
iv = xor(client_siv_share, notary_siv_share)
key = xor(client_swk_share, notary_swk_share)
# key = bytes.fromhex('6e9d09f4c698e46fad33ae5f296f930f')
nonce = iv + server_records0[:8]
# nonce = bytes.fromhex('5b8ff6b20000000000000001')
aad = server_records0[:8]+b'\x17\x03\x03'+num_to_bytes(len(server_records0)-8-16, 2)
# aad = bytes.fromhex('00000000000000011703030319')
data = server_records0[8:]
# data = bytes.fromhex('7c5be4523930edfbd9f1aa2e7164964634bed5de664a803ec1185ee7bfc82b7b3c8ad77ba9fd7aacceff6b08a5db665984a73a0f36cda88580087b752ab293c6263bde4cbfdda758fe04dc80a470e9e7e9eb86fac22270c517d6684cd73dabcb49688ff99dd607f9cf6037a18ae55aa8cc6eb2bbaf9b914ce23ef93cc21511f2549c42b851c0875ad7e5e4556f77f7ed034a2a9fe6bba3437422d8b172c484d0c2873cd672ae36355827772585f53247c9f399ff86a8159c3c6c81efc6bb70d83c8e837b362a455fef2d648ac184ad8f2a0f601d589e7a51b4529717aa252565f7b5ab791a09df7aa4137dc694b0398ac95ac983608ee4835218c75286a9542580fe1fbbcf6ca4cb9e12fcb86f149575e7c68150d1979563b7e1b80c968d42e53be671e3e2cbfaaf3fa5937c2a02bd586261616bb7d07c6a25013a03d09c1b9ae7107bc719eabfb2717cd1c964a439719ab590590e0258bef8cebfeac9ad93cd4973ba556fc55f0a217d98de1a4f5ab0ac1d12850df70915660a34714e45e0759069c6177b169f12faa67212632865249c6705bf93470fcd97a2afafff754b3e5165d9981be7294692b6dd42bf68da59bfa88e6a9f8c0d77fad93775054f2dc1fbaf42ab6d120c8db501f7526ed46bfab1a9b31e20588e2f58b1c0ca0f3f2122fa0aaccafb3129b6f0321ce1860f57571129eeb7e144e36deec6606b60640cb30e8c1ee729b58363386604b18c0ef315678c59c08bf937ea6e41d9c59e0fab40c934269f7cf4ff7d97951ef94a5f3ac2a819845ad4743ca3bc5c67966830bb0f8cc0e78c0c27d088bba95bb3fc6bc62c1f5aec7a9a557ef3ce854e5f1cf920d3a587c21ff47036e0414239dd52eb41d396acd572c27b2bd217daf3cf8e4cb834b8af15bd0ffc04b94977eaf02abdc4339ffd8de3a1ca7e833e1c77276bf45a2be1bb796c7aeafe6678acc95d0bbdc3d8738bbc62d50d8ef15c37f46cef0a21bfe970c74e121162fd864b70b00e1de2568685204316430267cb530a449096d13d95dd738c601d0ad91cea3ee702b92266924aa2c42be298f7cc5475635387f16c79dee1ed728dc1190d061b011f5f26197de998f796e0933a01770df6b502bd4b5a5a54e0eabf9febbb')
plaintext = aes128_gcm_decrypt(key, data, nonce, aad)
print(plaintext)
content_start=b'{\n'
content_end = b'}\r\n'
start = plaintext.find(content_start)
end = plaintext.find(content_end)
content = plaintext[start:(end+1)]
print(start, len(content))
ctt = '{' + ','.join([str(int(x)) for x in content]) + '}'
print(f'long[] exp_ct = {ctt};')
print(plaintext[0])
print(plaintext[407])