#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <array>

namespace quic_crypto {

// ── SHA-256 ──
std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len);

// ── HMAC-SHA256 ──
std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len,
                                     const uint8_t* data, size_t data_len);

// ── HKDF (RFC 5869) ──
std::array<uint8_t, 32> hkdf_extract(const uint8_t* salt, size_t salt_len,
                                      const uint8_t* ikm, size_t ikm_len);

std::vector<uint8_t> hkdf_expand(const uint8_t* prk, size_t prk_len,
                                  const uint8_t* info, size_t info_len,
                                  size_t out_len);

// ── HKDF-Expand-Label (TLS 1.3 / QUIC) ──
// label is WITHOUT the "tls13 " prefix (added internally)
std::vector<uint8_t> hkdf_expand_label(const uint8_t* secret, size_t secret_len,
                                        const std::string& label,
                                        const uint8_t* context, size_t context_len,
                                        size_t out_len);

// ── AES-128 ──
// Single-block AES-128 ECB encrypt (for header protection)
void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

// ── AES-128-GCM ──
// Returns true on success (tag matches), false on auth failure
bool aes128_gcm_decrypt(const uint8_t key[16],
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* ciphertext, size_t ct_len,
                         const uint8_t* tag, // 16 bytes
                         uint8_t* plaintext);

// ── QUIC Initial Decryption ──

struct QUICDecryptResult {
    bool success = false;
    std::vector<uint8_t> plaintext;  // Decrypted QUIC payload (CRYPTO frames etc.)
};

// Decrypt a QUIC Initial packet payload.
// buf points to the start of the QUIC packet (first byte = header form byte).
// len is the total length of the QUIC packet.
// Returns decrypted payload on success.
QUICDecryptResult decrypt_initial_packet(const uint8_t* buf, size_t len);

// Extract CRYPTO frame payload from decrypted Initial packet frames.
// Returns concatenated CRYPTO frame data (which contains the TLS ClientHello).
std::vector<uint8_t> extract_crypto_frames(const uint8_t* data, size_t len);

}  // namespace quic_crypto
