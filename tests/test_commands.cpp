#include <doctest/doctest.h>
#include <vaultcore/commands.hpp>

using namespace vaultcore;

TEST_CASE("tokenize") {
    SUBCASE("plain words") {
        auto r = tokenize("add GitHub --password abc");
        REQUIRE(r.ok());
        CHECK(*r.value == std::vector<std::string>{"add", "GitHub", "--password", "abc"});
    }
    SUBCASE("quoted strings keep spaces") {
        auto r = tokenize("add \"My Bank\" --notes \"two words\"");
        REQUIRE(r.ok());
        CHECK(*r.value ==
              std::vector<std::string>{"add", "My Bank", "--notes", "two words"});
    }
    SUBCASE("empty quoted string is a token") {
        auto r = tokenize("update X --notes \"\"");
        REQUIRE(r.ok());
        CHECK(*r.value == std::vector<std::string>{"update", "X", "--notes", ""});
    }
    SUBCASE("unclosed quote fails") {
        CHECK_FALSE(tokenize("add \"oops").ok());
    }
    SUBCASE("whitespace only yields no tokens") {
        auto r = tokenize("   ");
        REQUIRE(r.ok());
        CHECK(r.value->empty());
    }
}

TEST_CASE("command metadata") {
    CHECK(is_command_word("add"));
    CHECK(is_command_word("LIST"));
    CHECK_FALSE(is_command_word("frobnicate"));
    CHECK(usage_for("gen").find("--len") != std::string::npos);
    CHECK(usage_for("nope").empty());
    CHECK(help_text().find("retrieve <name>") != std::string::npos);
}
