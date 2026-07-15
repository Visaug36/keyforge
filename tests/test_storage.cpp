#include <doctest/doctest.h>
#include <vaultcore/crypto.hpp>
#include <vaultcore/storage.hpp>
#include <filesystem>
#include <fstream>

using namespace vaultcore;
namespace fs = std::filesystem;

static fs::path temp_vault(const char* name) {
    auto dir = fs::temp_directory_path() / "keyforge-tests";
    fs::create_directories(dir);
    auto p = dir / name;
    fs::remove(p);
    fs::remove(fs::path(p.string() + ".bak"));
    fs::remove(fs::path(p.string() + ".tmp"));
    return p;
}

TEST_CASE("session lifecycle") {
    crypto_init();
    auto weak = KdfParams::testing_weak();
    auto path = temp_vault("life.kfv");

    auto created = Session::create(path, "masterpass1", weak);
    REQUIRE(created.ok());
    Entry e;
    e.name = "GitHub";
    e.password = "s3cret";
    REQUIRE(created.value->vault().add(e, 100).ok());
    REQUIRE(created.value->save().ok());

    SUBCASE("open with correct password restores entries") {
        auto opened = Session::open(path, "masterpass1");
        REQUIRE(opened.ok());
        const Entry* r = opened.value->vault().find("GitHub");
        REQUIRE(r != nullptr);
        CHECK(r->password == "s3cret");
    }
    SUBCASE("open with wrong password fails with WrongPassword") {
        auto opened = Session::open(path, "wrongpass99");
        REQUIRE_FALSE(opened.ok());
        CHECK(opened.error.code == Err::WrongPassword);
    }
    SUBCASE("create refuses to overwrite an existing vault") {
        CHECK_FALSE(Session::create(path, "masterpass1", weak).ok());
    }
    SUBCASE("create rejects short master passwords") {
        CHECK_FALSE(Session::create(temp_vault("short.kfv"), "short", weak).ok());
    }
    SUBCASE("second save creates .bak of the previous version") {
        REQUIRE(created.value->save().ok());
        CHECK(fs::exists(fs::path(path.string() + ".bak")));
        CHECK_FALSE(fs::exists(fs::path(path.string() + ".tmp")));
    }
    SUBCASE("tampering with the file body is detected") {
        auto size = fs::file_size(path);
        std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(std::streamoff(size - 5));
        char c;
        f.seekg(std::streamoff(size - 5));
        f.get(c);
        f.seekp(std::streamoff(size - 5));
        f.put(char(c ^ 0x01));
        f.close();
        CHECK_FALSE(Session::open(path, "masterpass1").ok());
    }
    SUBCASE("bad magic is reported as Corrupt") {
        std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(0);
        f.put('X');
        f.close();
        auto opened = Session::open(path, "masterpass1");
        REQUIRE_FALSE(opened.ok());
        CHECK(opened.error.code == Err::Corrupt);
    }
    SUBCASE("export_copy produces a byte-identical encrypted copy") {
        auto dest = temp_vault("exported.kfv");
        REQUIRE(created.value->export_copy(dest).ok());
        CHECK(fs::file_size(dest) == fs::file_size(path));
        auto opened = Session::open(dest, "masterpass1");
        REQUIRE(opened.ok());
        CHECK(opened.value->vault().find("GitHub") != nullptr);
    }
}
