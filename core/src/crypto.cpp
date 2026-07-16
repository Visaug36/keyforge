#include "vaultcore/crypto.hpp"
#include <sodium.h>
#include <cstdlib>
#include <cstring>

namespace vaultcore {

static_assert(kSaltLen == crypto_pwhash_SALTBYTES);
static_assert(kNonceLen == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

SecureBuffer::SecureBuffer(size_t n) : size_(n) {
    data_ = static_cast<uint8_t*>(sodium_malloc(n ? n : 1));
    if (!data_) std::abort();  // out of locked memory: nothing sane to do
    std::memset(data_, 0, n ? n : 1);
}

SecureBuffer::~SecureBuffer() {
    if (data_) sodium_free(data_);  // sodium_free zeroes before releasing
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data_) sodium_free(data_);
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

KdfParams KdfParams::moderate() {
    return {crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE};
}

KdfParams KdfParams::testing_weak() {
    return {crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN};
}

void crypto_init() {
    if (sodium_init() < 0) std::abort();
}

std::array<uint8_t, kSaltLen> random_salt() {
    std::array<uint8_t, kSaltLen> s{};
    randombytes_buf(s.data(), s.size());
    return s;
}

std::array<uint8_t, kNonceLen> random_nonce() {
    std::array<uint8_t, kNonceLen> n{};
    randombytes_buf(n.data(), n.size());
    return n;
}

Result<SecureBuffer> derive_key(const std::string& password,
                                const std::array<uint8_t, kSaltLen>& salt,
                                const KdfParams& params) {
    SecureBuffer key(kKeyLen);
    if (crypto_pwhash(key.data(), kKeyLen, password.c_str(), password.size(),
                      salt.data(), params.opslimit, size_t(params.memlimit),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return Result<SecureBuffer>::failure(
            Err::Io, "key derivation failed (bad parameters or out of memory)");
    }
    return Result<SecureBuffer>::success(std::move(key));
}

std::vector<uint8_t> aead_encrypt(const SecureBuffer& key,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kNonceLen>& nonce) {
    std::vector<uint8_t> out(plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long outlen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(out.data(), &outlen,
                                               plaintext, plaintext_len,
                                               aad.data(), aad.size(),
                                               nullptr, nonce.data(), key.data());
    out.resize(size_t(outlen));
    return out;
}

Result<SecureBuffer> aead_decrypt(const SecureBuffer& key,
                                  const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kNonceLen>& nonce) {
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return Result<SecureBuffer>::failure(Err::Corrupt, "ciphertext too short");
    SecureBuffer out(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long outlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &outlen, nullptr,
                                                   ciphertext.data(), ciphertext.size(),
                                                   aad.data(), aad.size(),
                                                   nonce.data(), key.data()) != 0) {
        return Result<SecureBuffer>::failure(Err::WrongPassword, "authentication failed");
    }
    return Result<SecureBuffer>::success(std::move(out));
}

}  // namespace vaultcore
