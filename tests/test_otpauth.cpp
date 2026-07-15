#include <doctest/doctest.h>
#include <vaultcore/totp.hpp>

using namespace vaultcore;

TEST_CASE("otpauth uri parsing") {
    SUBCASE("full uri") {
        auto r = parse_otpauth_uri(
            "otpauth://totp/KeyForge:demo%40mail.com?secret=MZXW6YTB&issuer=KeyForge"
            "&digits=8&period=60");
        REQUIRE(r.ok());
        CHECK(r.value->secret == "MZXW6YTB");
        CHECK(r.value->digits == 8);
        CHECK(r.value->period == 60);
        CHECK(r.value->label == "KeyForge:demo@mail.com");
    }
    SUBCASE("minimal uri gets defaults") {
        auto r = parse_otpauth_uri("otpauth://totp/acct?secret=MZXW6YTB");
        REQUIRE(r.ok());
        CHECK(r.value->digits == 6);
        CHECK(r.value->period == 30);
    }
    SUBCASE("rejects non-totp scheme") {
        CHECK_FALSE(parse_otpauth_uri("otpauth://hotp/acct?secret=MZXW6YTB").ok());
        CHECK_FALSE(parse_otpauth_uri("https://example.com").ok());
    }
    SUBCASE("rejects missing or invalid secret") {
        CHECK_FALSE(parse_otpauth_uri("otpauth://totp/acct?issuer=x").ok());
        CHECK_FALSE(parse_otpauth_uri("otpauth://totp/acct").ok());
        CHECK_FALSE(parse_otpauth_uri("otpauth://totp/acct?secret=!!bad!!").ok());
    }
    SUBCASE("rejects out-of-range digits") {
        CHECK_FALSE(parse_otpauth_uri("otpauth://totp/a?secret=MZXW6YTB&digits=4").ok());
    }
}
