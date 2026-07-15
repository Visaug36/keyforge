#include <doctest/doctest.h>
#include <vaultcore/commands.hpp>
#include <vaultcore/crypto.hpp>
#include <vaultcore/storage.hpp>
#include <filesystem>
#include <fstream>

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

static vaultcore::Session make_session(const char* name) {
    namespace fs = std::filesystem;
    vaultcore::crypto_init();
    auto dir = fs::temp_directory_path() / "keyforge-tests";
    fs::create_directories(dir);
    auto p = dir / name;
    fs::remove(p);
    fs::remove(fs::path(p.string() + ".bak"));
    auto s = vaultcore::Session::create(p, "masterpass1",
                                        vaultcore::KdfParams::testing_weak());
    REQUIRE(s.ok());
    return std::move(*s.value);
}

TEST_CASE("dispatcher: add / list / show / retrieve / update / delete") {
    auto s = make_session("cmd.kfv");
    constexpr int64_t kNow = 1000;

    auto add = execute_command(
        s, "add GitHub --password pw1 --username naram --tags dev,work", kNow);
    CHECK(add.ok);
    CHECK(add.vault_changed);

    SUBCASE("duplicate add fails") {
        auto dup = execute_command(s, "add github --password x", kNow);
        CHECK_FALSE(dup.ok);
    }
    SUBCASE("add without --password fails") {
        CHECK_FALSE(execute_command(s, "add NoPw", kNow).ok);
    }
    SUBCASE("list and tag filter") {
        auto all = execute_command(s, "list", kNow);
        CHECK(all.kind == CommandOutcome::Kind::EntryList);
        CHECK(all.entries.size() == 1);
        auto none = execute_command(s, "list --tag banking", kNow);
        CHECK(none.entries.empty());
        auto tagged = execute_command(s, "list --tag dev", kNow);
        CHECK(tagged.entries.size() == 1);
    }
    SUBCASE("show returns detail") {
        auto out = execute_command(s, "show GitHub", kNow);
        CHECK(out.kind == CommandOutcome::Kind::EntryDetail);
        REQUIRE(out.entries.size() == 1);
        CHECK(out.entries[0].password == "pw1");
    }
    SUBCASE("retrieve copies to clipboard; --type selects field") {
        auto out = execute_command(s, "retrieve GitHub", kNow);
        CHECK(out.copy_to_clipboard);
        CHECK(out.secret == "pw1");
        auto user = execute_command(s, "retrieve GitHub --type username", kNow);
        CHECK(user.secret == "naram");
        CHECK_FALSE(execute_command(s, "retrieve GitHub --type urls", kNow).ok);
        CHECK_FALSE(execute_command(s, "retrieve GitHub --type url", kNow).ok);  // empty
    }
    SUBCASE("update replaces fields; bad update fails") {
        auto up = execute_command(s, "update GitHub --url https://github.com", kNow + 1);
        CHECK(up.ok);
        CHECK(execute_command(s, "show GitHub", kNow).entries[0].url ==
              "https://github.com");
        CHECK_FALSE(execute_command(s, "update GitHub", kNow).ok);   // nothing to update
        CHECK_FALSE(execute_command(s, "update Nope --url x", kNow).ok);
    }
    SUBCASE("delete requires --yes") {
        CHECK_FALSE(execute_command(s, "delete GitHub", kNow).ok);
        auto del = execute_command(s, "delete GitHub --yes", kNow);
        CHECK(del.ok);
        CHECK(del.vault_changed);
        CHECK_FALSE(execute_command(s, "show GitHub", kNow).ok);
    }
}

TEST_CASE("dispatcher: gen / totp / lock / audit / unknown / export-import") {
    auto s = make_session("cmd2.kfv");
    constexpr int64_t kNow = 59;  // RFC vector time

    SUBCASE("gen respects flags") {
        auto out = execute_command(s, "gen --len 32 --no-symbols", kNow);
        CHECK(out.kind == CommandOutcome::Kind::Secret);
        CHECK(out.secret.size() == 32);
        CHECK_FALSE(out.copy_to_clipboard);
        CHECK_FALSE(execute_command(s, "gen --len nope", kNow).ok);
    }
    SUBCASE("totp command and retrieve --type totp") {
        auto add = execute_command(
            s, "add Mail --password x --totp-secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            kNow);
        REQUIRE(add.ok);
        auto t = execute_command(s, "totp Mail", kNow);
        CHECK(t.kind == CommandOutcome::Kind::Totp);
        CHECK(t.secret == "287082");
        CHECK(t.totp_entry == "Mail");
        auto r = execute_command(s, "retrieve Mail --type totp", kNow);
        CHECK(r.secret == "287082");
        auto none = execute_command(s, "add Plain --password y", kNow);
        REQUIRE(none.ok);
        CHECK_FALSE(execute_command(s, "totp Plain", kNow).ok);
    }
    SUBCASE("invalid totp secret on add fails") {
        CHECK_FALSE(execute_command(s, "add Bad --password x --totp-secret !!!", kNow).ok);
        CHECK_FALSE(execute_command(
            s, "add Bad --password x --totp-secret AAAA --totp-uri otpauth://x", kNow).ok);
    }
    SUBCASE("lock sets the flag") {
        CHECK(execute_command(s, "lock", kNow).lock_requested);
    }
    SUBCASE("audit reports weak password") {
        REQUIRE(execute_command(s, "add W --password abc", kNow).ok);
        auto out = execute_command(s, "audit", kNow);
        CHECK(out.message.find("weak") != std::string::npos);
    }
    SUBCASE("unknown command suggests nearest") {
        auto out = execute_command(s, "delte X", kNow);
        CHECK_FALSE(out.ok);
        CHECK(out.message.find("delete") != std::string::npos);
    }
    SUBCASE("export then import roundtrip via csv") {
        namespace fs = std::filesystem;
        REQUIRE(execute_command(s, "add A --password pw", kNow).ok);
        auto dest = (fs::temp_directory_path() / "keyforge-tests" / "exp.kfv").string();
        auto ex = execute_command(s, "export \"" + dest + "\"", kNow);
        CHECK(ex.ok);
        CHECK(fs::exists(dest));

        auto csvp = (fs::temp_directory_path() / "keyforge-tests" / "imp.csv").string();
        std::ofstream(csvp) << "name,url,username,password,notes\nNewOne,,,npw,\n";
        auto im = execute_command(s, "import \"" + csvp + "\"", kNow);
        CHECK(im.ok);
        CHECK(im.vault_changed);
        CHECK(execute_command(s, "show NewOne", kNow).ok);
        CHECK_FALSE(execute_command(s, "import \"" + csvp + "\" --format xml", kNow).ok);
    }
}
