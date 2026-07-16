#include <doctest/doctest.h>
#include <vaultcore/vault.hpp>

using namespace vaultcore;

static Entry make(const std::string& name, const std::string& pw) {
    Entry e;
    e.name = name;
    e.password = pw;
    return e;
}

TEST_CASE("vault CRUD") {
    Vault v;
    CHECK(v.add(make("GitHub", "pw1"), 1000).ok());
    CHECK(v.add(make("Steam", "pw2"), 1000).ok());

    SUBCASE("duplicate name rejected, case-insensitively") {
        CHECK_FALSE(v.add(make("github", "x"), 1001).ok());
    }
    SUBCASE("empty name rejected") {
        CHECK_FALSE(v.add(make("", "x"), 1001).ok());
    }
    SUBCASE("find is case-insensitive") {
        REQUIRE(v.find("github") != nullptr);
        CHECK(v.find("github")->password == "pw1");
        CHECK(v.find("nope") == nullptr);
    }
    SUBCASE("add sets timestamps") {
        const Entry* e = v.find("GitHub");
        CHECK(e->created_at == 1000);
        CHECK(e->updated_at == 1000);
        CHECK(e->password_changed_at == 1000);
    }
    SUBCASE("update patches only given fields; password bumps password_changed_at") {
        EntryPatch p;
        p.username = "naram";
        CHECK(v.update_entry("GitHub", p, 2000).ok());
        CHECK(v.find("GitHub")->username == "naram");
        CHECK(v.find("GitHub")->password == "pw1");
        CHECK(v.find("GitHub")->password_changed_at == 1000);
        CHECK(v.find("GitHub")->updated_at == 2000);

        EntryPatch p2;
        p2.password = "newpw";
        CHECK(v.update_entry("GitHub", p2, 3000).ok());
        CHECK(v.find("GitHub")->password_changed_at == 3000);
    }
    SUBCASE("update with empty patch or missing entry fails") {
        CHECK_FALSE(v.update_entry("GitHub", EntryPatch{}, 2000).ok());
        EntryPatch p;
        p.notes = "x";
        CHECK_FALSE(v.update_entry("nope", p, 2000).ok());
    }
    SUBCASE("tags are replaced wholesale") {
        EntryPatch p;
        p.tags = std::vector<std::string>{"dev", "work"};
        CHECK(v.update_entry("GitHub", p, 2000).ok());
        CHECK(v.find("GitHub")->tags == std::vector<std::string>{"dev", "work"});
        EntryPatch p2;
        p2.tags = std::vector<std::string>{"solo"};
        CHECK(v.update_entry("GitHub", p2, 2001).ok());
        CHECK(v.find("GitHub")->tags == std::vector<std::string>{"solo"});
    }
    SUBCASE("remove") {
        CHECK(v.remove("steam").ok());
        CHECK(v.find("Steam") == nullptr);
        CHECK_FALSE(v.remove("Steam").ok());
    }
}

TEST_CASE("list and search") {
    Vault v;
    Entry a = make("Matrix", "1");
    a.tags = {"chat"};
    Entry b = make("MatrixEmail", "2");
    b.username = "neo@matrix.org";
    Entry c = make("Steam", "3");
    c.url = "https://store.steampowered.com";
    REQUIRE(v.add(a, 1).ok());
    REQUIRE(v.add(c, 1).ok());
    REQUIRE(v.add(b, 1).ok());

    SUBCASE("list is sorted by name and filters by tag") {
        auto all = v.list();
        REQUIRE(all.size() == 3);
        CHECK(all[0]->name == "Matrix");
        CHECK(all[1]->name == "MatrixEmail");
        CHECK(all[2]->name == "Steam");
        auto tagged = v.list("CHAT");
        REQUIRE(tagged.size() == 1);
        CHECK(tagged[0]->name == "Matrix");
    }
    SUBCASE("search matches name, username, url, tags — case-insensitive") {
        CHECK(v.search("matrix").size() == 2);
        CHECK(v.search("neo@").size() == 1);
        CHECK(v.search("steampowered").size() == 1);
        CHECK(v.search("chat").size() == 1);
        CHECK(v.search("zzz").empty());
    }
}

TEST_CASE("json roundtrip") {
    Vault v;
    Entry e = make("GitHub", "s3cret");
    e.username = "naram";
    e.url = "https://github.com";
    e.notes = "two lines\nhere";
    e.tags = {"dev", "work"};
    e.totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    REQUIRE(v.add(e, 42).ok());
    v.settings().auto_lock_min = 9;
    v.settings().gen_symbols = false;

    auto restored = Vault::from_json(v.to_json());
    REQUIRE(restored.ok());
    const Entry* r = restored.value->find("GitHub");
    REQUIRE(r != nullptr);
    CHECK(r->password == "s3cret");
    CHECK(r->notes == "two lines\nhere");
    CHECK(r->tags == std::vector<std::string>{"dev", "work"});
    CHECK(r->totp_secret == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    CHECK(r->created_at == 42);
    CHECK(restored.value->settings().auto_lock_min == 9);
    CHECK(restored.value->settings().gen_symbols == false);
}

TEST_CASE("from_json rejects garbage") {
    CHECK_FALSE(Vault::from_json("not json at all").ok());
    CHECK_FALSE(Vault::from_json("[1,2,3]").ok());
}

TEST_CASE("all_tags: sorted, case-insensitively deduplicated") {
    Vault v;
    Entry a = make("A", "1"); a.tags = {"Dev", "work"};
    Entry b = make("B", "2"); b.tags = {"dev", "School"};
    Entry c = make("C", "3");  // no tags
    REQUIRE(v.add(a, 1).ok());
    REQUIRE(v.add(b, 1).ok());
    REQUIRE(v.add(c, 1).ok());

    auto tags = v.all_tags();
    // "Dev"/"dev" collapse to one (first-seen casing kept); sorted case-insensitively.
    REQUIRE(tags.size() == 3);
    CHECK(tags[0] == "Dev");
    CHECK(tags[1] == "School");
    CHECK(tags[2] == "work");
}

TEST_CASE("all_tags: empty vault yields no tags") {
    Vault v;
    CHECK(v.all_tags().empty());
}
