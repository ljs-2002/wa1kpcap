#define NOMINMAX

#include "quic_crypto.h"
#include <cstring>
#include <algorithm>
#include <stdexcept>

namespace quic_crypto {

// ============================================================================
// SHA-256 (FIPS 180-4)
// ============================================================================

namespace {

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t Sigma0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
inline uint32_t Sigma1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
inline uint32_t sigma0_(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
inline uint32_t sigma1_(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

inline uint32_t load_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  | uint32_t(p[3]);
}

inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);  p[3] = uint8_t(v);
}

inline void store_be64(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; --i) { p[i] = uint8_t(v & 0xff); v >>= 8; }
}

struct SHA256State {
    uint32_t h[8];
    uint8_t block[64];
    size_t block_len;
    uint64_t total_len;

    SHA256State() : block_len(0), total_len(0) {
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
    }

    void process_block(const uint8_t* data) {
        uint32_t W[64];
        for (int i = 0; i < 16; ++i) W[i] = load_be32(data + i * 4);
        for (int i = 16; i < 64; ++i)
            W[i] = sigma1_(W[i-2]) + W[i-7] + sigma0_(W[i-15]) + W[i-16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = hh + Sigma1(e) + Ch(e, f, g) + SHA256_K[i] + W[i];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);
            hh = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;
        if (block_len > 0) {
            size_t fill = 64 - block_len;
            if (len < fill) {
                std::memcpy(block + block_len, data, len);
                block_len += len;
                return;
            }
            std::memcpy(block + block_len, data, fill);
            process_block(block);
            data += fill;
            len -= fill;
            block_len = 0;
        }
        while (len >= 64) {
            process_block(data);
            data += 64;
            len -= 64;
        }
        if (len > 0) {
            std::memcpy(block, data, len);
            block_len = len;
        }
    }

    std::array<uint8_t, 32> finalize() {
        uint64_t bits = total_len * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (block_len != 56) {
            update(&zero, 1);
        }
        uint8_t len_bytes[8];
        store_be64(len_bytes, bits);
        update(len_bytes, 8);

        std::array<uint8_t, 32> digest;
        for (int i = 0; i < 8; ++i) store_be32(digest.data() + i * 4, h[i]);
        return digest;
    }
};

} // anonymous namespace

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    SHA256State state;
    state.update(data, len);
    return state.finalize();
}

// ============================================================================
// HMAC-SHA256 (RFC 2104)
// ============================================================================

std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len,
                                     const uint8_t* data, size_t data_len) {
    uint8_t k_pad[64];
    std::memset(k_pad, 0, 64);

    if (key_len > 64) {
        auto hashed = sha256(key, key_len);
        std::memcpy(k_pad, hashed.data(), 32);
    } else {
        std::memcpy(k_pad, key, key_len);
    }

    // Inner hash: H(ipad_key || message)
    uint8_t ipad[64];
    for (int i = 0; i < 64; ++i) ipad[i] = k_pad[i] ^ 0x36;

    SHA256State inner;
    inner.update(ipad, 64);
    inner.update(data, data_len);
    auto inner_hash = inner.finalize();

    // Outer hash: H(opad_key || inner_hash)
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) opad[i] = k_pad[i] ^ 0x5c;

    SHA256State outer;
    outer.update(opad, 64);
    outer.update(inner_hash.data(), 32);
    return outer.finalize();
}

// ============================================================================
// HKDF (RFC 5869)
// ============================================================================

std::array<uint8_t, 32> hkdf_extract(const uint8_t* salt, size_t salt_len,
                                      const uint8_t* ikm, size_t ikm_len) {
    if (salt == nullptr || salt_len == 0) {
        uint8_t zero_salt[32] = {};
        return hmac_sha256(zero_salt, 32, ikm, ikm_len);
    }
    return hmac_sha256(salt, salt_len, ikm, ikm_len);
}

std::vector<uint8_t> hkdf_expand(const uint8_t* prk, size_t prk_len,
                                  const uint8_t* info, size_t info_len,
                                  size_t out_len) {
    size_t N = (out_len + 31) / 32;
    if (N > 255) throw std::runtime_error("hkdf_expand: out_len too large");

    std::vector<uint8_t> result;
    result.reserve(out_len);

    std::array<uint8_t, 32> T_prev = {};
    size_t T_prev_len = 0;

    for (size_t i = 1; i <= N; ++i) {
        std::vector<uint8_t> msg;
        msg.reserve(T_prev_len + info_len + 1);
        if (T_prev_len > 0)
            msg.insert(msg.end(), T_prev.begin(), T_prev.begin() + T_prev_len);
        if (info_len > 0)
            msg.insert(msg.end(), info, info + info_len);
        msg.push_back(static_cast<uint8_t>(i));

        T_prev = hmac_sha256(prk, prk_len, msg.data(), msg.size());
        T_prev_len = 32;

        size_t to_copy = (std::min)(static_cast<size_t>(32), out_len - result.size());
        result.insert(result.end(), T_prev.begin(), T_prev.begin() + to_copy);
    }

    return result;
}

// ============================================================================
// HKDF-Expand-Label (TLS 1.3 / QUIC RFC 9001)
// ============================================================================

std::vector<uint8_t> hkdf_expand_label(const uint8_t* secret, size_t secret_len,
                                        const std::string& label,
                                        const uint8_t* context, size_t context_len,
                                        size_t out_len) {
    std::string full_label = "tls13 " + label;
    if (full_label.size() > 255) throw std::runtime_error("label too long");

    std::vector<uint8_t> info;
    info.reserve(2 + 1 + full_label.size() + 1 + context_len);

    // uint16 length
    info.push_back(static_cast<uint8_t>((out_len >> 8) & 0xff));
    info.push_back(static_cast<uint8_t>(out_len & 0xff));

    // opaque label<7..255>
    info.push_back(static_cast<uint8_t>(full_label.size()));
    info.insert(info.end(), full_label.begin(), full_label.end());

    // opaque context<0..255>
    info.push_back(static_cast<uint8_t>(context_len));
    if (context_len > 0)
        info.insert(info.end(), context, context + context_len);

    return hkdf_expand(secret, secret_len, info.data(), info.size(), out_len);
}

// ============================================================================
// AES-128 ECB Encrypt
// ============================================================================

namespace {

static const uint8_t AES_SBOX[256] = {
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t AES_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// xtime: multiply by 2 in GF(2^8)
inline uint8_t xtime(uint8_t x) {
    return uint8_t((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

struct AES128 {
    uint8_t round_keys[176]; // 11 round keys * 16 bytes

    void key_expansion(const uint8_t key[16]) {
        std::memcpy(round_keys, key, 16);
        for (int i = 4; i < 44; ++i) {
            uint8_t temp[4];
            std::memcpy(temp, round_keys + (i - 1) * 4, 4);
            if (i % 4 == 0) {
                // RotWord
                uint8_t t = temp[0];
                temp[0] = AES_SBOX[temp[1]];
                temp[1] = AES_SBOX[temp[2]];
                temp[2] = AES_SBOX[temp[3]];
                temp[3] = AES_SBOX[t];
                temp[0] ^= AES_RCON[i / 4];
            }
            for (int j = 0; j < 4; ++j)
                round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j];
        }
    }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        // Initial AddRoundKey
        add_round_key(state, 0);

        // Rounds 1-9
        for (int round = 1; round <= 9; ++round) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }

        // Round 10 (no MixColumns)
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, 10);

        std::memcpy(out, state, 16);
    }

private:
    void add_round_key(uint8_t state[16], int round) const {
        for (int i = 0; i < 16; ++i)
            state[i] ^= round_keys[round * 16 + i];
    }

    static void sub_bytes(uint8_t state[16]) {
        for (int i = 0; i < 16; ++i)
            state[i] = AES_SBOX[state[i]];
    }

    static void shift_rows(uint8_t state[16]) {
        // Row 0: no shift
        // Row 1: shift left 1
        uint8_t t = state[1];
        state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
        // Row 2: shift left 2
        t = state[2]; state[2] = state[10]; state[10] = t;
        t = state[6]; state[6] = state[14]; state[14] = t;
        // Row 3: shift left 3
        t = state[15];
        state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
    }

    static void mix_columns(uint8_t state[16]) {
        for (int c = 0; c < 4; ++c) {
            int i = c * 4;
            uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
            state[i]   = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            state[i+1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            state[i+2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            state[i+3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        }
    }
};

} // anonymous namespace

void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    AES128 aes;
    aes.key_expansion(key);
    aes.encrypt_block(in, out);
}

// ============================================================================
// AES-128-GCM Decrypt
// ============================================================================

namespace {

// GF(2^128) multiplication for GHASH
// X and Y are 16-byte blocks in big-endian bit order
void ghash_gf_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t result[16]) {
    uint8_t V[16];
    std::memcpy(V, Y, 16);
    std::memset(result, 0, 16);

    for (int i = 0; i < 128; ++i) {
        // If bit i of X is set (MSB first)
        if (X[i / 8] & (0x80 >> (i % 8))) {
            for (int j = 0; j < 16; ++j)
                result[j] ^= V[j];
        }
        // V = V >> 1 in GF(2^128), with reduction polynomial x^128 + x^7 + x^2 + x + 1
        uint8_t lsb = V[15] & 1;
        for (int j = 15; j > 0; --j)
            V[j] = (V[j] >> 1) | (V[j-1] << 7);
        V[0] >>= 1;
        if (lsb)
            V[0] ^= 0xe1; // reduction: XOR with R = 0xe1000...0
    }
}

// GHASH: iterative multiplication over 16-byte blocks
// data must be a multiple of 16 bytes (caller pads)
void ghash(const uint8_t H[16], const uint8_t* data, size_t data_len, uint8_t tag[16]) {
    std::memset(tag, 0, 16);
    for (size_t i = 0; i < data_len; i += 16) {
        for (int j = 0; j < 16; ++j)
            tag[j] ^= data[i + j];
        uint8_t tmp[16];
        ghash_gf_mul(tag, H, tmp);
        std::memcpy(tag, tmp, 16);
    }
}

// Increment the rightmost 32 bits of a 16-byte counter block
void gcm_inc32(uint8_t counter[16]) {
    for (int i = 15; i >= 12; --i) {
        if (++counter[i] != 0) break;
    }
}

} // anonymous namespace

bool aes128_gcm_decrypt(const uint8_t key[16],
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* ciphertext, size_t ct_len,
                         const uint8_t* tag,
                         uint8_t* plaintext) {
    AES128 aes;
    aes.key_expansion(key);

    // H = AES(key, 0^128)
    uint8_t H[16] = {};
    aes.encrypt_block(H, H);

    // Compute J0 (initial counter)
    uint8_t J0[16] = {};
    if (iv_len == 12) {
        // Common case: J0 = IV || 0x00000001
        std::memcpy(J0, iv, 12);
        J0[15] = 0x01;
    } else {
        // General case: J0 = GHASH(H, pad(IV) || len64(IV))
        size_t iv_padded_len = ((iv_len + 15) / 16) * 16;
        std::vector<uint8_t> iv_block(iv_padded_len + 16, 0);
        std::memcpy(iv_block.data(), iv, iv_len);
        // Last 16 bytes: 0^64 || len(IV) in bits as 64-bit BE
        uint64_t iv_bits = static_cast<uint64_t>(iv_len) * 8;
        store_be64(iv_block.data() + iv_padded_len + 8, iv_bits);
        ghash(H, iv_block.data(), iv_block.size(), J0);
    }

    // AES-CTR decryption: counter starts at J0 + 1 (= counter 2 for 12-byte IV)
    uint8_t counter[16];
    std::memcpy(counter, J0, 16);
    gcm_inc32(counter); // Now counter = 2

    for (size_t i = 0; i < ct_len; i += 16) {
        uint8_t keystream[16];
        aes.encrypt_block(counter, keystream);
        gcm_inc32(counter);

        size_t block_len = (std::min)(static_cast<size_t>(16), ct_len - i);
        for (size_t j = 0; j < block_len; ++j)
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
    }

    // Compute GHASH over AAD and ciphertext
    // Pad AAD to 16-byte boundary
    size_t aad_padded_len = ((aad_len + 15) / 16) * 16;
    // Pad ciphertext to 16-byte boundary
    size_t ct_padded_len = ((ct_len + 15) / 16) * 16;
    // Total: padded_aad + padded_ct + 16 bytes (len(A) || len(C))
    size_t ghash_input_len = aad_padded_len + ct_padded_len + 16;
    std::vector<uint8_t> ghash_input(ghash_input_len, 0);

    if (aad_len > 0)
        std::memcpy(ghash_input.data(), aad, aad_len);
    if (ct_len > 0)
        std::memcpy(ghash_input.data() + aad_padded_len, ciphertext, ct_len);

    // Last 16 bytes: len(A) in bits (64-bit BE) || len(C) in bits (64-bit BE)
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits = static_cast<uint64_t>(ct_len) * 8;
    store_be64(ghash_input.data() + aad_padded_len + ct_padded_len, aad_bits);
    store_be64(ghash_input.data() + aad_padded_len + ct_padded_len + 8, ct_bits);

    uint8_t S[16];
    ghash(H, ghash_input.data(), ghash_input_len, S);

    // T = S XOR AES(key, J0)
    uint8_t enc_j0[16];
    aes.encrypt_block(J0, enc_j0);
    uint8_t computed_tag[16];
    for (int i = 0; i < 16; ++i)
        computed_tag[i] = S[i] ^ enc_j0[i];

    // Constant-time tag comparison
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i)
        diff |= computed_tag[i] ^ tag[i];

    if (diff != 0) {
        // Authentication failed - clear plaintext
        std::memset(plaintext, 0, ct_len);
        return false;
    }
    return true;
}

// ============================================================================
// QUIC Variable-Length Integer Encoding (RFC 9000 Section 16)
// ============================================================================

namespace {

// Decode a QUIC variable-length integer. Returns the value and advances pos.
// Returns false if there is not enough data.
bool decode_varint(const uint8_t* buf, size_t len, size_t& pos, uint64_t& value) {
    if (pos >= len) return false;
    uint8_t first = buf[pos];
    uint8_t prefix = first >> 6;
    size_t varint_len = static_cast<size_t>(1) << prefix; // 1, 2, 4, or 8

    if (pos + varint_len > len) return false;

    value = first & 0x3f;
    for (size_t i = 1; i < varint_len; ++i) {
        value = (value << 8) | buf[pos + i];
    }
    pos += varint_len;
    return true;
}

// Encode a uint64 as big-endian into a buffer of specified width
void encode_be(uint8_t* out, uint64_t val, size_t width) {
    for (size_t i = 0; i < width; ++i) {
        out[width - 1 - i] = static_cast<uint8_t>(val & 0xff);
        val >>= 8;
    }
}

} // anonymous namespace

// ============================================================================
// QUIC Initial Packet Decryption (RFC 9001)
// ============================================================================

QUICDecryptResult decrypt_initial_packet(const uint8_t* buf, size_t len) {
    QUICDecryptResult fail;

    // Minimum QUIC long header size check
    if (len < 10) return fail;

    size_t pos = 0;
    uint8_t first_byte = buf[pos++];

    // Must be Long Header (bit 7 = 1)
    if ((first_byte & 0x80) == 0) return fail;

    // Version
    if (pos + 4 > len) return fail;
    uint32_t version = (uint32_t(buf[pos]) << 24) | (uint32_t(buf[pos+1]) << 16) |
                       (uint32_t(buf[pos+2]) << 8) | uint32_t(buf[pos+3]);
    pos += 4;

    // Select salt based on version
    const uint8_t* salt = nullptr;
    size_t salt_len = 20;

    // QUIC v1 (RFC 9001)
    static const uint8_t QUIC_V1_SALT[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    // QUIC v2 (RFC 9369)
    static const uint8_t QUIC_V2_SALT[20] = {
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
    };

    // Check packet type: for v1, Initial = 0b00; for v2, Initial = 0b01
    uint8_t packet_type = (first_byte >> 4) & 0x03;

    if (version == 0x00000001 || version == 0xff00001d || version == 0xff00001e ||
        version == 0xff00001f || version == 0xff000020) {
        // QUIC v1 and late drafts
        if (packet_type != 0x00) return fail; // Not Initial
        salt = QUIC_V1_SALT;
    } else if (version == 0x6b3343cf) {
        // QUIC v2
        if (packet_type != 0x01) return fail; // v2 Initial type is 0b01
        salt = QUIC_V2_SALT;
    } else {
        // Unknown version - try v1 salt with type 0x00
        if (packet_type != 0x00) return fail;
        salt = QUIC_V1_SALT;
    }

    // DCID
    if (pos >= len) return fail;
    uint8_t dcid_len = buf[pos++];
    if (dcid_len > 20 || pos + dcid_len > len) return fail;
    const uint8_t* dcid = buf + pos;
    pos += dcid_len;

    // SCID
    if (pos >= len) return fail;
    uint8_t scid_len = buf[pos++];
    if (scid_len > 20 || pos + scid_len > len) return fail;
    pos += scid_len;

    // Token (varint length + token bytes)
    uint64_t token_len = 0;
    if (!decode_varint(buf, len, pos, token_len)) return fail;
    if (pos + token_len > len) return fail;
    pos += static_cast<size_t>(token_len);

    // Payload length (varint)
    uint64_t payload_len = 0;
    if (!decode_varint(buf, len, pos, payload_len)) return fail;

    // pos now points to the start of the packet number field
    size_t pn_offset = pos;

    // Ensure we have enough data for the payload
    if (pn_offset + payload_len > len) return fail;
    if (payload_len < 20) return fail; // Need at least 4 (max PN) + 16 (tag)

    // -- Derive keys --

    // initial_secret = HKDF-Extract(salt, DCID)
    auto initial_secret = hkdf_extract(salt, salt_len, dcid, dcid_len);

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    auto client_secret = hkdf_expand_label(
        initial_secret.data(), initial_secret.size(),
        "client in", nullptr, 0, 32);

    // key = HKDF-Expand-Label(client_secret, "quic key", "", 16)
    auto quic_key = hkdf_expand_label(
        client_secret.data(), client_secret.size(),
        "quic key", nullptr, 0, 16);

    // iv = HKDF-Expand-Label(client_secret, "quic iv", "", 12)
    auto quic_iv = hkdf_expand_label(
        client_secret.data(), client_secret.size(),
        "quic iv", nullptr, 0, 12);

    // hp_key = HKDF-Expand-Label(client_secret, "quic hp", "", 16)
    auto hp_key = hkdf_expand_label(
        client_secret.data(), client_secret.size(),
        "quic hp", nullptr, 0, 16);

    // -- Remove header protection --

    // Sample starts at pn_offset + 4, 16 bytes
    size_t sample_offset = pn_offset + 4;
    if (sample_offset + 16 > pn_offset + static_cast<size_t>(payload_len)) return fail;
    if (sample_offset + 16 > len) return fail;

    uint8_t mask[16];
    aes128_ecb_encrypt(hp_key.data(), buf + sample_offset, mask);

    // Work on a mutable copy of the header
    std::vector<uint8_t> header(buf, buf + pn_offset + 4); // max 4 PN bytes

    // Unmask first byte: for long header, mask lower 4 bits
    header[0] = first_byte ^ (mask[0] & 0x0f);

    // Determine packet number length from unmasked first byte (bits 0-1)
    size_t pn_len = (header[0] & 0x03) + 1; // 1-4 bytes

    // Unmask packet number bytes
    for (size_t i = 0; i < pn_len; ++i) {
        header[pn_offset + i] = buf[pn_offset + i] ^ mask[1 + i];
    }

    // Reconstruct packet number
    uint32_t pn = 0;
    for (size_t i = 0; i < pn_len; ++i) {
        pn = (pn << 8) | header[pn_offset + i];
    }

    // -- Construct nonce --
    // nonce = iv XOR packet_number (PN padded to 12 bytes, left-padded with zeros)
    uint8_t nonce[12];
    std::memcpy(nonce, quic_iv.data(), 12);
    // XOR PN into the last bytes of the nonce
    uint8_t pn_bytes[12] = {};
    encode_be(pn_bytes, pn, 12);
    for (int i = 0; i < 12; ++i)
        nonce[i] ^= pn_bytes[i];

    // -- Build AAD --
    // AAD = the header bytes from start up to and including the packet number
    size_t aad_len = pn_offset + pn_len;
    std::vector<uint8_t> aad(aad_len);
    // Copy original bytes, then overwrite with unmasked header
    std::memcpy(aad.data(), buf, aad_len);
    // Overwrite first byte with unmasked version
    aad[0] = header[0];
    // Overwrite PN bytes with unmasked version
    for (size_t i = 0; i < pn_len; ++i)
        aad[pn_offset + i] = header[pn_offset + i];

    // -- Decrypt payload --
    // Ciphertext starts after the packet number
    size_t ct_offset = pn_offset + pn_len;
    size_t ct_plus_tag_len = static_cast<size_t>(payload_len) - pn_len;
    if (ct_plus_tag_len < 16) return fail; // Need at least the 16-byte tag
    size_t ct_len = ct_plus_tag_len - 16;
    const uint8_t* ciphertext = buf + ct_offset;
    const uint8_t* tag = buf + ct_offset + ct_len;

    std::vector<uint8_t> plaintext(ct_len);
    bool ok = aes128_gcm_decrypt(
        quic_key.data(), nonce, 12,
        aad.data(), aad_len,
        ciphertext, ct_len,
        tag,
        ct_len > 0 ? plaintext.data() : nullptr);

    if (!ok) return fail;

    QUICDecryptResult result;
    result.success = true;
    result.plaintext = std::move(plaintext);
    return result;
}

// ============================================================================
// Extract CRYPTO frames from decrypted QUIC Initial payload
// ============================================================================

std::vector<uint8_t> extract_crypto_frames(const uint8_t* data, size_t len) {
    std::vector<uint8_t> result;
    size_t pos = 0;

    while (pos < len) {
        // Read frame type (varint)
        uint64_t frame_type = 0;
        if (!decode_varint(data, len, pos, frame_type)) break;

        if (frame_type == 0x00) {
            // PADDING frame: single byte, no payload
            continue;
        } else if (frame_type == 0x01) {
            // PING frame: no payload
            continue;
        } else if (frame_type == 0x02 || frame_type == 0x03) {
            // ACK frame: skip it
            uint64_t largest_ack = 0, ack_delay = 0, ack_range_count = 0, first_range = 0;
            if (!decode_varint(data, len, pos, largest_ack)) break;
            if (!decode_varint(data, len, pos, ack_delay)) break;
            if (!decode_varint(data, len, pos, ack_range_count)) break;
            if (!decode_varint(data, len, pos, first_range)) break;
            for (uint64_t i = 0; i < ack_range_count; ++i) {
                uint64_t gap = 0, range = 0;
                if (!decode_varint(data, len, pos, gap)) return result;
                if (!decode_varint(data, len, pos, range)) return result;
            }
            if (frame_type == 0x03) {
                // ACK_ECN: 3 additional varint fields
                uint64_t ect0 = 0, ect1 = 0, ecn_ce = 0;
                if (!decode_varint(data, len, pos, ect0)) break;
                if (!decode_varint(data, len, pos, ect1)) break;
                if (!decode_varint(data, len, pos, ecn_ce)) break;
            }
            continue;
        } else if (frame_type == 0x06) {
            // CRYPTO frame: offset (varint) + length (varint) + data
            uint64_t offset = 0, crypto_len = 0;
            if (!decode_varint(data, len, pos, offset)) break;
            if (!decode_varint(data, len, pos, crypto_len)) break;
            if (pos + crypto_len > len) break;
            result.insert(result.end(), data + pos, data + pos + crypto_len);
            pos += static_cast<size_t>(crypto_len);
            continue;
        } else if (frame_type == 0x1c || frame_type == 0x1d) {
            // CONNECTION_CLOSE frame
            uint64_t error_code = 0, frame_type_cc = 0, reason_len = 0;
            if (!decode_varint(data, len, pos, error_code)) break;
            if (frame_type == 0x1c) {
                if (!decode_varint(data, len, pos, frame_type_cc)) break;
            }
            if (!decode_varint(data, len, pos, reason_len)) break;
            if (pos + reason_len > len) break;
            pos += static_cast<size_t>(reason_len);
            continue;
        } else {
            // Unknown frame type — can't safely skip, stop parsing
            break;
        }
    }

    return result;
}

}  // namespace quic_crypto
