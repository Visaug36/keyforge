#include <doctest/doctest.h>
#include <vaultcore/totp.hpp>
#include <string>
#include <vector>

using namespace vaultcore;

// RFC 6238 test secret: ASCII "12345678901234567890" in base32.
static const char* kRfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

TEST_CASE("base32 decode") {
    SUBCASE("known vectors (RFC 4648)") {
        auto r = base32_decode("MZXW6YTB");
        REQUIRE(r.ok());
        CHECK(std::string(r.value->begin(), r.value->end()) == "fooba");
        auto r2 = base32_decode("MZXW6===");
        REQUIRE(r2.ok());
        CHECK(std::string(r2.value->begin(), r2.value->end()) == "foo");
    }
    SUBCASE("lowercase and spaces tolerated") {
        auto r = base32_decode("mzxw 6ytb");
        REQUIRE(r.ok());
        CHECK(std::string(r.value->begin(), r.value->end()) == "fooba");
    }
    SUBCASE("invalid characters rejected") {
        CHECK_FALSE(base32_decode("MZXW8YTB").ok());  // '8' is not base32
        CHECK_FALSE(base32_decode("").ok());
    }
}

TEST_CASE("totp matches RFC 6238 SHA-1 test vectors (8 digits)") {
    struct V { int64_t t; const char* code; };
    std::vector<V> vs = {{59, "94287082"},
                         {1111111109, "07081804"},
                         {1111111111, "14050471"},
                         {1234567890, "89005924"},
                         {2000000000, "69279037"},
                         {20000000000LL, "65353130"}};
    for (const auto& v : vs) {
        auto r = totp_code(kRfcSecret, v.t, 8, 30);
        REQUIRE(r.ok());
        CHECK(*r.value == v.code);
    }
}

TEST_CASE("totp 6-digit default and remaining seconds") {
    auto r = totp_code(kRfcSecret, 59);
    REQUIRE(r.ok());
    CHECK(*r.value == "287082");
    CHECK(totp_seconds_remaining(59) == 1);
    CHECK(totp_seconds_remaining(60) == 30);
    CHECK_FALSE(totp_code(kRfcSecret, 59, 9).ok());   // digits out of range
    CHECK_FALSE(totp_code("!!notbase32!!", 59).ok());
}
