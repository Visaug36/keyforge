#include <doctest/doctest.h>
#include <vaultcore/porting.hpp>
#include <vaultcore/vault.hpp>

using namespace vaultcore;

TEST_CASE("csv import — chrome column layout") {
    Vault v;
    std::string csv =
        "name,url,username,password,note\n"  // chrome calls it "note"; we accept notes too
        "GitHub,https://github.com,naram,pw1,\n"
        "Steam,https://steampowered.com,gamer,pw2,\"line1\nline2\"\n";
    // Our reader requires "notes" or "note" for the notes column:
    auto r = import_csv(v, csv, 500);
    REQUIRE(r.ok());
    CHECK(r.value->imported == 2);
    CHECK(r.value->skipped.empty());
    REQUIRE(v.find("Steam") != nullptr);
    CHECK(v.find("Steam")->notes == "line1\nline2");
    CHECK(v.find("GitHub")->username == "naram");
    CHECK(v.find("GitHub")->created_at == 500);
}

TEST_CASE("csv import — bitwarden column layout") {
    Vault v;
    std::string csv =
        "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n"
        ",,login,Matrix,my note,,https://matrix.org,neo,pw9,\n";
    auto r = import_csv(v, csv, 500);
    REQUIRE(r.ok());
    CHECK(r.value->imported == 1);
    REQUIRE(v.find("Matrix") != nullptr);
    CHECK(v.find("Matrix")->password == "pw9");
    CHECK(v.find("Matrix")->url == "https://matrix.org");
    CHECK(v.find("Matrix")->notes == "my note");
}

TEST_CASE("csv import — skips bad rows and duplicates with reasons") {
    Vault v;
    Entry existing;
    existing.name = "GitHub";
    existing.password = "x";
    REQUIRE(v.add(existing, 1).ok());
    std::string csv =
        "name,url,username,password,notes\n"
        "GitHub,,,pw1,\n"
        ",,,pw2,\n"
        "Fresh,,,pw3,\n";
    auto r = import_csv(v, csv, 500);
    REQUIRE(r.ok());
    CHECK(r.value->imported == 1);
    REQUIRE(r.value->skipped.size() == 2);
    CHECK(r.value->skipped[0].find("row 2") != std::string::npos);
    CHECK(r.value->skipped[1].find("row 3") != std::string::npos);
    CHECK(v.find("Fresh") != nullptr);
}

TEST_CASE("csv import — rejects files without required columns") {
    Vault v;
    CHECK_FALSE(import_csv(v, "a,b\n1,2\n", 1).ok());
    CHECK_FALSE(import_csv(v, "", 1).ok());
}
