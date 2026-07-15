#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "result.hpp"

namespace vaultcore {

constexpr size_t kSaltLen = 16;   // == crypto_pwhash_SALTBYTES
constexpr size_t kNonceLen = 24;  // == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
constexpr size_t kKeyLen = 32;

// Owns sodium_malloc'ed guarded memory: mlocked, canary-guarded, zeroed on free.
class SecureBuffer {
public:
    explicit SecureBuffer(size_t n);
    ~SecureBuffer();
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    uint8_t* data() { return data_; }
    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }

private:
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
};

struct KdfParams {
    uint64_t opslimit = 0;
    uint64_t memlimit = 0;
    static KdfParams moderate();      // production default (Argon2id MODERATE)
    static KdfParams testing_weak();  // MIN limits — unit tests ONLY, never for real vaults
};

// Call once at startup. Aborts if libsodium cannot initialize (no safe fallback).
void crypto_init();

std::array<uint8_t, kSaltLen> random_salt();
std::array<uint8_t, kNonceLen> random_nonce();

Result<SecureBuffer> derive_key(const std::string& password,
                                const std::array<uint8_t, kSaltLen>& salt,
                                const KdfParams& params);

std::vector<uint8_t> aead_encrypt(const SecureBuffer& key,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kNonceLen>& nonce);

Result<SecureBuffer> aead_decrypt(const SecureBuffer& key,
                                  const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kNonceLen>& nonce);

}  // namespace vaultcore
