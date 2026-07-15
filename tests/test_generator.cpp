#include <doctest/doctest.h>
#include <vaultcore/crypto.hpp>
#include <vaultcore/generator.hpp>
#include <string>

using namespace vaultcore;

static bool contains_any(const std::string& s, const std::string& set) {
    return s.find_first_of(set) != std::string::npos;
}

TEST_CASE("generator") {
    crypto_init();

    SUBCASE("default: 20 chars with upper, lower, digit, symbol; no ambiguous") {
        for (int i = 0; i < 50; ++i) {
            auto r = generate_password(GenOptions{});
            REQUIRE(r.ok());
            const std::string& p = *r.value;
            CHECK(p.size() == 20);
            CHECK(contains_any(p, "abcdefghijkmnopqrstuvwxyz"));
            CHECK(contains_any(p, "ABCDEFGHJKLMNPQRSTUVWXYZ"));
            CHECK(contains_any(p, "23456789"));
            CHECK(contains_any(p, "!@#$%^&*()-_=+[]{};:,.?"));
            CHECK_FALSE(contains_any(p, "0O1lI"));
        }
    }
    SUBCASE("--no-symbols excludes symbols") {
        GenOptions o;
        o.symbols = false;
        for (int i = 0; i < 20; ++i) {
            auto r = generate_password(o);
            REQUIRE(r.ok());
            CHECK_FALSE(contains_any(*r.value, "!@#$%^&*()-_=+[]{};:,.?"));
        }
    }
    SUBCASE("custom length respected") {
        GenOptions o;
        o.length = 64;
        auto r = generate_password(o);
        REQUIRE(r.ok());
        CHECK(r.value->size() == 64);
    }
    SUBCASE("length bounds enforced") {
        GenOptions bad;
        bad.length = 3;
        CHECK_FALSE(generate_password(bad).ok());
        bad.length = 129;
        CHECK_FALSE(generate_password(bad).ok());
    }
    SUBCASE("two generations differ") {
        auto a = generate_password(GenOptions{});
        auto b = generate_password(GenOptions{});
        REQUIRE(a.ok());
        REQUIRE(b.ok());
        CHECK(*a.value != *b.value);
    }
}
