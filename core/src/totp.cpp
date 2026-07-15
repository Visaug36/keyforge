#include "vaultcore/totp.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

namespace vaultcore {
namespace {

// Compact SHA-1 (FIPS 180-1). SHA-1 is required by the TOTP/HOTP standard for
// authenticator compatibility; HMAC-SHA1 is not affected by SHA-1 collisions.
struct Sha1 {
    uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    uint64_t len = 0;
    uint8_t buf[64];
    size_t buflen = 0;

    static uint32_t rol(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }

    void block(const uint8_t* p) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[4 * i]) << 24) | (uint32_t(p[4 * i + 1]) << 16) |
                   (uint32_t(p[4 * i + 2]) << 8) | uint32_t(p[4 * i + 3]);
        for (int i = 16; i < 80; ++i)
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999u; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
            uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    void update(const uint8_t* p, size_t n) {
        len += n;
        while (n) {
            size_t take = std::min(n, size_t(64) - buflen);
            std::memcpy(buf + buflen, p, take);
            buflen += take; p += take; n -= take;
            if (buflen == 64) { block(buf); buflen = 0; }
        }
    }

    std::array<uint8_t, 20> final() {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t z = 0;
        while (buflen != 56) update(&z, 1);
        uint8_t lb[8];
        for (int i = 0; i < 8; ++i) lb[i] = uint8_t(bits >> (56 - 8 * i));
        update(lb, 8);
        std::array<uint8_t, 20> out;
        for (int i = 0; i < 5; ++i) {
            out[4 * i] = uint8_t(h[i] >> 24);
            out[4 * i + 1] = uint8_t(h[i] >> 16);
            out[4 * i + 2] = uint8_t(h[i] >> 8);
            out[4 * i + 3] = uint8_t(h[i]);
        }
        return out;
    }
};

std::array<uint8_t, 20> hmac_sha1(const uint8_t* key, size_t keylen,
                                  const uint8_t* msg, size_t msglen) {
    uint8_t k[64] = {0};
    if (keylen > 64) {
        Sha1 s;
        s.update(key, keylen);
        auto d = s.final();
        std::memcpy(k, d.data(), 20);
    } else {
        std::memcpy(k, key, keylen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5C; }
    Sha1 inner;
    inner.update(ipad, 64);
    inner.update(msg, msglen);
    auto ih = inner.final();
    Sha1 outer;
    outer.update(opad, 64);
    outer.update(ih.data(), 20);
    return outer.final();
}

}  // namespace

Result<std::vector<uint8_t>> base32_decode(std::string_view s) {
    std::vector<uint8_t> out;
    uint32_t bits = 0;
    int nbits = 0;
    for (char c : s) {
        if (c == ' ' || c == '-' || c == '=') continue;
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else return Result<std::vector<uint8_t>>::failure(Err::BadBase32,
                                                          "invalid base32 character");
        bits = (bits << 5) | uint32_t(v);
        nbits += 5;
        if (nbits >= 8) {
            out.push_back(uint8_t(bits >> (nbits - 8)));
            nbits -= 8;
        }
    }
    if (out.empty())
        return Result<std::vector<uint8_t>>::failure(Err::BadBase32, "empty base32 secret");
    return Result<std::vector<uint8_t>>::success(std::move(out));
}

Result<std::string> totp_code(std::string_view base32_secret, int64_t unix_time,
                              int digits, int period) {
    if (digits < 6 || digits > 8)
        return Result<std::string>::failure(Err::BadArgs, "digits must be 6-8");
    if (period <= 0)
        return Result<std::string>::failure(Err::BadArgs, "period must be positive");
    auto key = base32_decode(base32_secret);
    if (!key.ok()) return Result<std::string>::failure(key.error.code, key.error.message);
    uint64_t counter = uint64_t(unix_time / period);
    uint8_t msg[8];
    for (int i = 0; i < 8; ++i) msg[i] = uint8_t(counter >> (56 - 8 * i));
    auto h = hmac_sha1(key.value->data(), key.value->size(), msg, 8);
    int off = h[19] & 0x0F;
    uint32_t bin = (uint32_t(h[off] & 0x7F) << 24) | (uint32_t(h[off + 1]) << 16) |
                   (uint32_t(h[off + 2]) << 8) | uint32_t(h[off + 3]);
    uint32_t mod = 1;
    for (int i = 0; i < digits; ++i) mod *= 10;
    char buf[16];
    std::snprintf(buf, sizeof buf, "%0*u", digits, bin % mod);
    return Result<std::string>::success(std::string(buf));
}

int totp_seconds_remaining(int64_t unix_time, int period) {
    return period - int(unix_time % period);
}

}  // namespace vaultcore
