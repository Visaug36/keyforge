#include <doctest/doctest.h>
#include <vaultcore/crypto.hpp>
#include <cstring>
#include <string>
#include <vector>

using namespace vaultcore;

TEST_CASE("aead roundtrip, wrong key, and tamper detection") {
    crypto_init();
    auto params = KdfParams::testing_weak();
    auto salt = random_salt();
    auto key = derive_key("correct horse battery", salt, params);
    REQUIRE(key.ok());

    std::string msg = "{\"hello\":\"vault\"}";
    std::vector<uint8_t> aad = {1, 2, 3, 4};
    auto nonce = random_nonce();
    auto cipher = aead_encrypt(*key.value, reinterpret_cast<const uint8_t*>(msg.data()),
                               msg.size(), aad, nonce);
    CHECK(cipher.size() == msg.size() + 16);  // + Poly1305 tag

    auto plain = aead_decrypt(*key.value, cipher, aad, nonce);
    REQUIRE(plain.ok());
    CHECK(std::string(reinterpret_cast<const char*>(plain.value->data()),
                      plain.value->size()) == msg);

    SUBCASE("wrong password fails to decrypt") {
        auto key2 = derive_key("wrong password", salt, params);
        REQUIRE(key2.ok());
        CHECK_FALSE(aead_decrypt(*key2.value, cipher, aad, nonce).ok());
    }
    SUBCASE("every flipped ciphertext byte fails authentication") {
        for (size_t i = 0; i < cipher.size(); ++i) {
            auto bad = cipher;
            bad[i] ^= 0x01;
            CHECK_FALSE(aead_decrypt(*key.value, bad, aad, nonce).ok());
        }
    }
    SUBCASE("tampered aad fails authentication") {
        auto bad_aad = aad;
        bad_aad[0] ^= 0x01;
        CHECK_FALSE(aead_decrypt(*key.value, cipher, bad_aad, nonce).ok());
    }
    SUBCASE("same password + salt derives the same key") {
        auto key2 = derive_key("correct horse battery", salt, params);
        REQUIRE(key2.ok());
        CHECK(std::memcmp(key.value->data(), key2.value->data(), kKeyLen) == 0);
    }
    SUBCASE("different salt derives a different key") {
        auto salt2 = random_salt();
        auto key2 = derive_key("correct horse battery", salt2, params);
        REQUIRE(key2.ok());
        CHECK(std::memcmp(key.value->data(), key2.value->data(), kKeyLen) != 0);
    }
}
