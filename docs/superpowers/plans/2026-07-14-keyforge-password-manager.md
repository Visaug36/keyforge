# KeyForge Password Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Bitwarden-style, fully local password manager: encrypted single-file vault, desktop GUI with a command palette, TOTP, generator, audit, import/export.

**Architecture:** `vaultcore` static library holds ALL logic (crypto, vault, storage, TOTP, commands) with zero UI code; a thin Dear ImGui + GLFW shell renders the palette. Vault = one file: authenticated header (Argon2id params, salt, nonce) + XChaCha20-Poly1305 ciphertext of a JSON payload.

**Tech Stack:** C++20, CMake ≥3.24 (FetchContent for everything), libsodium (via robinlinden/libsodium-cmake), nlohmann/json, Dear ImGui + GLFW + OpenGL, quirc + stb_image (QR), doctest.

**Spec:** `docs/superpowers/specs/2026-07-14-keyforge-password-manager-design.md`

**Conventions used throughout:**
- All core code lives in `namespace vaultcore`. Entry names are matched case-insensitively.
- Errors flow through `Result<T>` / `Status` (defined in Task 1) — core never throws to callers, never prints, never aborts (except unrecoverable `sodium_init` failure).
- Every task: write failing test → run (expect FAIL) → implement → run (expect PASS) → commit.
- Build commands assume repo root. First configure downloads all deps (2–5 min). Test binary: `./build/tests/core_tests`.
- Run tests with: `cmake --build build && ./build/tests/core_tests` (ctest works too; direct invocation shows doctest detail).

---

### Task 1: Project skeleton, dependencies, first passing test

**Files:**
- Create: `CMakeLists.txt`, `.gitignore`, `core/CMakeLists.txt`, `core/include/vaultcore/result.hpp`, `core/include/vaultcore/util.hpp`, `core/include/vaultcore/paths.hpp`, `core/src/paths.cpp`, `tests/CMakeLists.txt`, `tests/main.cpp`, `tests/test_paths.cpp`

- [ ] **Step 1: Write the repo scaffolding**

`.gitignore`:
```
build/
.DS_Store
*.kfv
*.kfv.bak
```

`CMakeLists.txt` (root):
```cmake
cmake_minimum_required(VERSION 3.24)
project(keyforge LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG master)
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)

FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3)

FetchContent_Declare(doctest
  GIT_REPOSITORY https://github.com/doctest/doctest.git
  GIT_TAG v2.4.11)

FetchContent_Declare(glfw
  GIT_REPOSITORY https://github.com/glfw/glfw.git
  GIT_TAG 3.4)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(imgui
  GIT_REPOSITORY https://github.com/ocornut/imgui.git
  GIT_TAG v1.90.9)

FetchContent_Declare(quirc
  GIT_REPOSITORY https://github.com/dlbeer/quirc.git
  GIT_TAG v1.2)

FetchContent_Declare(stb
  GIT_REPOSITORY https://github.com/nothings/stb.git
  GIT_TAG master)

FetchContent_MakeAvailable(sodium json doctest glfw imgui quirc stb)

# imgui has no CMakeLists — build it as a static lib with the glfw/opengl3 backends.
add_library(imgui STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_demo.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp)
target_include_directories(imgui PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends)
target_link_libraries(imgui PUBLIC glfw)

# quirc has no CMakeLists — build its 4 C files.
add_library(quirc STATIC
  ${quirc_SOURCE_DIR}/lib/decode.c
  ${quirc_SOURCE_DIR}/lib/identify.c
  ${quirc_SOURCE_DIR}/lib/quirc.c
  ${quirc_SOURCE_DIR}/lib/version_db.c)
target_include_directories(quirc PUBLIC ${quirc_SOURCE_DIR}/lib)

add_subdirectory(core)

enable_testing()
add_subdirectory(tests)
```

`core/CMakeLists.txt`:
```cmake
add_library(vaultcore STATIC
  src/paths.cpp)
target_include_directories(vaultcore PUBLIC include PRIVATE ${stb_SOURCE_DIR})
target_link_libraries(vaultcore PUBLIC sodium nlohmann_json::nlohmann_json PRIVATE quirc)
```

`core/include/vaultcore/result.hpp`:
```cpp
#pragma once
#include <optional>
#include <string>
#include <utility>

namespace vaultcore {

enum class Err {
    None, Io, WrongPassword, Corrupt, NotFound, Duplicate,
    BadArgs, BadBase32, BadUri, BadQr, BadCsv, UnknownCommand
};

struct Error {
    Err code = Err::None;
    std::string message;
};

// For operations with no return value.
struct Status {
    Error error;
    bool ok() const { return error.code == Err::None; }
    static Status success() { return {}; }
    static Status failure(Err c, std::string m) { return {{c, std::move(m)}}; }
};

// For operations that return a value. Check ok() before dereferencing value.
template <typename T>
struct Result {
    std::optional<T> value;
    Error error;
    bool ok() const { return value.has_value(); }
    static Result success(T v) { Result r; r.value = std::move(v); return r; }
    static Result failure(Err c, std::string m) { Result r; r.error = {c, std::move(m)}; return r; }
};

}  // namespace vaultcore
```

`core/include/vaultcore/util.hpp`:
```cpp
#pragma once
#include <algorithm>
#include <cctype>
#include <string>

namespace vaultcore {

inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

inline bool iequals(const std::string& a, const std::string& b) {
    return to_lower(a) == to_lower(b);
}

}  // namespace vaultcore
```

`core/include/vaultcore/paths.hpp`:
```cpp
#pragma once
#include <filesystem>

namespace vaultcore {

// OS-standard per-user data dir for keyforge (created lazily by callers):
// macOS: ~/Library/Application Support/keyforge
// Linux: $XDG_DATA_HOME/keyforge or ~/.local/share/keyforge
// Windows: %APPDATA%/keyforge
std::filesystem::path default_vault_dir();

}  // namespace vaultcore
```

`core/src/paths.cpp`:
```cpp
#include "vaultcore/paths.hpp"
#include <cstdlib>

namespace vaultcore {

std::filesystem::path default_vault_dir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    return std::filesystem::path(appdata ? appdata : ".") / "keyforge";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    return std::filesystem::path(home ? home : ".") / "Library" / "Application Support" / "keyforge";
#else
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && *xdg) return std::filesystem::path(xdg) / "keyforge";
    const char* home = std::getenv("HOME");
    return std::filesystem::path(home ? home : ".") / ".local" / "share" / "keyforge";
#endif
}

}  // namespace vaultcore
```

`tests/CMakeLists.txt`:
```cmake
add_executable(core_tests
  main.cpp
  test_paths.cpp)
target_link_libraries(core_tests PRIVATE vaultcore doctest::doctest)
target_compile_definitions(core_tests PRIVATE TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
add_test(NAME core_tests COMMAND core_tests)
```

`tests/main.cpp`:
```cpp
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
```

`tests/test_paths.cpp`:
```cpp
#include <doctest/doctest.h>
#include <vaultcore/paths.hpp>

TEST_CASE("default vault dir is non-empty and ends with keyforge") {
    auto p = vaultcore::default_vault_dir();
    CHECK(!p.empty());
    CHECK(p.filename() == "keyforge");
}
```

- [ ] **Step 2: Configure and build (downloads all deps — takes minutes the first time)**

Run: `cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j`
Expected: configures and builds with no errors (warnings from third-party code are fine).

- [ ] **Step 3: Run the test**

Run: `./build/tests/core_tests`
Expected: `[doctest] Status: SUCCESS!` with 1 test case passed.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: project skeleton with CMake deps, Result type, paths"
```

---

### Task 2: Crypto primitives (SecureBuffer, Argon2id KDF, XChaCha20-Poly1305 AEAD)

**Files:**
- Create: `core/include/vaultcore/crypto.hpp`, `core/src/crypto.cpp`, `tests/test_crypto.cpp`
- Modify: `core/CMakeLists.txt` (add `src/crypto.cpp`), `tests/CMakeLists.txt` (add `test_crypto.cpp`)

- [ ] **Step 1: Write the failing tests**

`tests/test_crypto.cpp`:
```cpp
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
```

Add `test_crypto.cpp` to the `add_executable(core_tests ...)` list in `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/crypto.hpp` not found.

- [ ] **Step 3: Implement**

`core/include/vaultcore/crypto.hpp`:
```cpp
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "result.hpp"

namespace vaultcore {

constexpr size_t kSaltLen = 16;   // == crypto_pwhash_SALTBYTES
constexpr size_t kNonceLen = 24;  // == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
constexpr size_t kKeyLen = 32;

// Owns sodium_malloc'ed guarded memory: mlocked, canary-guarded, zeroed on free.
class SecureBuffer {
public:
    explicit SecureBuffer(size_t n);
    ~SecureBuffer();
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    uint8_t* data() { return data_; }
    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }

private:
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
};

struct KdfParams {
    uint64_t opslimit = 0;
    uint64_t memlimit = 0;
    static KdfParams moderate();      // production default (Argon2id MODERATE)
    static KdfParams testing_weak();  // MIN limits — unit tests ONLY, never for real vaults
};

// Call once at startup. Aborts if libsodium cannot initialize (no safe fallback).
void crypto_init();

std::array<uint8_t, kSaltLen> random_salt();
std::array<uint8_t, kNonceLen> random_nonce();

Result<SecureBuffer> derive_key(const std::string& password,
                                const std::array<uint8_t, kSaltLen>& salt,
                                const KdfParams& params);

std::vector<uint8_t> aead_encrypt(const SecureBuffer& key,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kNonceLen>& nonce);

Result<SecureBuffer> aead_decrypt(const SecureBuffer& key,
                                  const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kNonceLen>& nonce);

}  // namespace vaultcore
```

`core/src/crypto.cpp`:
```cpp
#include "vaultcore/crypto.hpp"
#include <sodium.h>
#include <cstdlib>
#include <cstring>

namespace vaultcore {

static_assert(kSaltLen == crypto_pwhash_SALTBYTES);
static_assert(kNonceLen == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

SecureBuffer::SecureBuffer(size_t n) : size_(n) {
    data_ = static_cast<uint8_t*>(sodium_malloc(n ? n : 1));
    if (!data_) std::abort();  // out of locked memory: nothing sane to do
    std::memset(data_, 0, n ? n : 1);
}

SecureBuffer::~SecureBuffer() {
    if (data_) sodium_free(data_);  // sodium_free zeroes before releasing
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data_) sodium_free(data_);
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

KdfParams KdfParams::moderate() {
    return {crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE};
}

KdfParams KdfParams::testing_weak() {
    return {crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN};
}

void crypto_init() {
    if (sodium_init() < 0) std::abort();
}

std::array<uint8_t, kSaltLen> random_salt() {
    std::array<uint8_t, kSaltLen> s{};
    randombytes_buf(s.data(), s.size());
    return s;
}

std::array<uint8_t, kNonceLen> random_nonce() {
    std::array<uint8_t, kNonceLen> n{};
    randombytes_buf(n.data(), n.size());
    return n;
}

Result<SecureBuffer> derive_key(const std::string& password,
                                const std::array<uint8_t, kSaltLen>& salt,
                                const KdfParams& params) {
    SecureBuffer key(kKeyLen);
    if (crypto_pwhash(key.data(), kKeyLen, password.c_str(), password.size(),
                      salt.data(), params.opslimit, size_t(params.memlimit),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return Result<SecureBuffer>::failure(
            Err::Io, "key derivation failed (bad parameters or out of memory)");
    }
    return Result<SecureBuffer>::success(std::move(key));
}

std::vector<uint8_t> aead_encrypt(const SecureBuffer& key,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kNonceLen>& nonce) {
    std::vector<uint8_t> out(plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long outlen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(out.data(), &outlen,
                                               plaintext, plaintext_len,
                                               aad.data(), aad.size(),
                                               nullptr, nonce.data(), key.data());
    out.resize(size_t(outlen));
    return out;
}

Result<SecureBuffer> aead_decrypt(const SecureBuffer& key,
                                  const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& aad,
                                  const std::array<uint8_t, kNonceLen>& nonce) {
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return Result<SecureBuffer>::failure(Err::Corrupt, "ciphertext too short");
    SecureBuffer out(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long outlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &outlen, nullptr,
                                                   ciphertext.data(), ciphertext.size(),
                                                   aad.data(), aad.size(),
                                                   nonce.data(), key.data()) != 0) {
        return Result<SecureBuffer>::failure(Err::WrongPassword, "authentication failed");
    }
    return Result<SecureBuffer>::success(std::move(out));
}

}  // namespace vaultcore
```

Add `src/crypto.cpp` to `add_library(vaultcore ...)` in `core/CMakeLists.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS, 2 test cases.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: SecureBuffer, Argon2id KDF, XChaCha20-Poly1305 AEAD"
```

---

### Task 3: Vault model + JSON serialization

**Files:**
- Create: `core/include/vaultcore/vault.hpp`, `core/src/vault.cpp`, `tests/test_vault.cpp`
- Modify: `core/CMakeLists.txt` (add `src/vault.cpp`), `tests/CMakeLists.txt` (add `test_vault.cpp`)

- [ ] **Step 1: Write the failing tests**

`tests/test_vault.cpp`:
```cpp
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
```

Add `test_vault.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/vault.hpp` not found.

- [ ] **Step 3: Implement**

`core/include/vaultcore/vault.hpp`:
```cpp
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "result.hpp"

namespace vaultcore {

struct Entry {
    std::string name;  // unique key, matched case-insensitively
    std::string username, password, url, notes;
    std::vector<std::string> tags;
    std::string totp_secret;  // base32; empty = no TOTP
    int64_t created_at = 0, updated_at = 0, password_changed_at = 0;
};

// Fields set here overwrite the entry's fields wholesale.
struct EntryPatch {
    std::optional<std::string> username, password, url, notes, totp_secret;
    std::optional<std::vector<std::string>> tags;
    bool empty() const {
        return !username && !password && !url && !notes && !totp_secret && !tags;
    }
};

struct Settings {
    int auto_lock_min = 5;
    int clip_clear_sec = 30;
    int gen_len = 20;
    bool gen_symbols = true;
};

class Vault {
public:
    Status add(Entry e, int64_t now);
    Status update_entry(const std::string& name, const EntryPatch& p, int64_t now);
    Status remove(const std::string& name);
    const Entry* find(const std::string& name) const;
    std::vector<const Entry*> list(const std::string& tag = "") const;   // name-sorted
    std::vector<const Entry*> search(const std::string& query) const;    // name-sorted
    const std::vector<Entry>& entries() const { return entries_; }
    Settings& settings() { return settings_; }
    const Settings& settings() const { return settings_; }
    std::string to_json() const;
    static Result<Vault> from_json(const std::string& text);

private:
    Entry* find_mutable(const std::string& name);
    std::vector<Entry> entries_;
    Settings settings_;
};

}  // namespace vaultcore
```

`core/src/vault.cpp`:
```cpp
#include "vaultcore/vault.hpp"
#include "vaultcore/util.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>

namespace vaultcore {

namespace {
void sort_by_name(std::vector<const Entry*>& v) {
    std::sort(v.begin(), v.end(), [](const Entry* a, const Entry* b) {
        return to_lower(a->name) < to_lower(b->name);
    });
}
}  // namespace

Status Vault::add(Entry e, int64_t now) {
    if (e.name.empty()) return Status::failure(Err::BadArgs, "entry name is required");
    if (find(e.name))
        return Status::failure(Err::Duplicate, "an entry named '" + e.name + "' already exists");
    e.created_at = e.updated_at = now;
    e.password_changed_at = e.password.empty() ? 0 : now;
    entries_.push_back(std::move(e));
    return Status::success();
}

Status Vault::update_entry(const std::string& name, const EntryPatch& p, int64_t now) {
    Entry* e = find_mutable(name);
    if (!e) return Status::failure(Err::NotFound, "no entry named '" + name + "'");
    if (p.empty()) return Status::failure(Err::BadArgs, "nothing to update");
    if (p.username) e->username = *p.username;
    if (p.password) { e->password = *p.password; e->password_changed_at = now; }
    if (p.url) e->url = *p.url;
    if (p.notes) e->notes = *p.notes;
    if (p.totp_secret) e->totp_secret = *p.totp_secret;
    if (p.tags) e->tags = *p.tags;
    e->updated_at = now;
    return Status::success();
}

Status Vault::remove(const std::string& name) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [&](const Entry& e) { return iequals(e.name, name); });
    if (it == entries_.end())
        return Status::failure(Err::NotFound, "no entry named '" + name + "'");
    entries_.erase(it);
    return Status::success();
}

const Entry* Vault::find(const std::string& name) const {
    for (const auto& e : entries_)
        if (iequals(e.name, name)) return &e;
    return nullptr;
}

Entry* Vault::find_mutable(const std::string& name) {
    for (auto& e : entries_)
        if (iequals(e.name, name)) return &e;
    return nullptr;
}

std::vector<const Entry*> Vault::list(const std::string& tag) const {
    std::vector<const Entry*> out;
    for (const auto& e : entries_) {
        if (tag.empty()) { out.push_back(&e); continue; }
        for (const auto& t : e.tags)
            if (iequals(t, tag)) { out.push_back(&e); break; }
    }
    sort_by_name(out);
    return out;
}

std::vector<const Entry*> Vault::search(const std::string& query) const {
    std::string q = to_lower(query);
    std::vector<const Entry*> out;
    for (const auto& e : entries_) {
        std::string hay = to_lower(e.name) + " " + to_lower(e.username) + " " + to_lower(e.url);
        for (const auto& t : e.tags) hay += " " + to_lower(t);
        if (hay.find(q) != std::string::npos) out.push_back(&e);
    }
    sort_by_name(out);
    return out;
}

std::string Vault::to_json() const {
    nlohmann::json j;
    j["settings"] = {{"auto_lock_min", settings_.auto_lock_min},
                     {"clip_clear_sec", settings_.clip_clear_sec},
                     {"gen_len", settings_.gen_len},
                     {"gen_symbols", settings_.gen_symbols}};
    j["entries"] = nlohmann::json::array();
    for (const auto& e : entries_) {
        j["entries"].push_back({{"name", e.name},
                                {"username", e.username},
                                {"password", e.password},
                                {"url", e.url},
                                {"notes", e.notes},
                                {"tags", e.tags},
                                {"totp_secret", e.totp_secret},
                                {"created_at", e.created_at},
                                {"updated_at", e.updated_at},
                                {"password_changed_at", e.password_changed_at}});
    }
    return j.dump();
}

Result<Vault> Vault::from_json(const std::string& text) {
    auto j = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return Result<Vault>::failure(Err::Corrupt, "vault payload is not valid JSON");
    Vault v;
    const auto s = j.value("settings", nlohmann::json::object());
    v.settings_.auto_lock_min = s.value("auto_lock_min", 5);
    v.settings_.clip_clear_sec = s.value("clip_clear_sec", 30);
    v.settings_.gen_len = s.value("gen_len", 20);
    v.settings_.gen_symbols = s.value("gen_symbols", true);
    for (const auto& je : j.value("entries", nlohmann::json::array())) {
        if (!je.is_object()) continue;
        Entry e;
        e.name = je.value("name", "");
        e.username = je.value("username", "");
        e.password = je.value("password", "");
        e.url = je.value("url", "");
        e.notes = je.value("notes", "");
        e.tags = je.value("tags", std::vector<std::string>{});
        e.totp_secret = je.value("totp_secret", "");
        e.created_at = je.value("created_at", int64_t{0});
        e.updated_at = je.value("updated_at", int64_t{0});
        e.password_changed_at = je.value("password_changed_at", int64_t{0});
        if (!e.name.empty()) v.entries_.push_back(std::move(e));
    }
    return Result<Vault>::success(std::move(v));
}

}  // namespace vaultcore
```

Add `src/vault.cpp` to `core/CMakeLists.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS, all test cases pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: vault model with CRUD, search, tags, JSON serialization"
```

---

### Task 4: Encrypted storage — Session create/open/save with atomic writes and .bak

**Files:**
- Create: `core/include/vaultcore/storage.hpp`, `core/src/storage.cpp`, `tests/test_storage.cpp`
- Modify: `core/CMakeLists.txt` (add `src/storage.cpp`), `tests/CMakeLists.txt` (add `test_storage.cpp`)

- [ ] **Step 1: Write the failing tests**

`tests/test_storage.cpp`:
```cpp
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
```

Add `test_storage.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/storage.hpp` not found.

- [ ] **Step 3: Implement**

`core/include/vaultcore/storage.hpp`:
```cpp
#pragma once
#include <filesystem>
#include "crypto.hpp"
#include "vault.hpp"

namespace vaultcore {

// An unlocked vault bound to its file and encryption key.
// Locking == destroying the Session (SecureBuffer wipes the key).
class Session {
public:
    static Result<Session> create(const std::filesystem::path& file,
                                  const std::string& master_password,
                                  KdfParams params = KdfParams::moderate());
    static Result<Session> open(const std::filesystem::path& file,
                                const std::string& master_password);
    Status save();  // atomic: tmp + fsync + rename; previous file kept as .bak
    Status export_copy(const std::filesystem::path& dest) const;
    Vault& vault() { return vault_; }
    const std::filesystem::path& path() const { return path_; }

    Session(Session&&) = default;
    Session& operator=(Session&&) = default;

private:
    Session(std::filesystem::path p, KdfParams params,
            std::array<uint8_t, kSaltLen> salt, SecureBuffer key, Vault v)
        : path_(std::move(p)), params_(params), salt_(salt),
          key_(std::move(key)), vault_(std::move(v)) {}
    std::filesystem::path path_;
    KdfParams params_;
    std::array<uint8_t, kSaltLen> salt_;
    SecureBuffer key_;
    Vault vault_;
};

}  // namespace vaultcore
```

`core/src/storage.cpp`:
```cpp
#include "vaultcore/storage.hpp"
#include <sodium.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace vaultcore {
namespace {

constexpr char kMagic[4] = {'K', 'F', 'V', '1'};
constexpr uint8_t kVersion = 1;
// magic(4) + version(1) + opslimit(8) + memlimit(8) + salt(16) + nonce(24)
constexpr size_t kHeaderLen = 61;

void put_u64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(uint8_t(x >> (8 * i)));  // little-endian
}

uint64_t get_u64(const uint8_t* p) {
    uint64_t x = 0;
    for (int i = 0; i < 8; ++i) x |= uint64_t(p[i]) << (8 * i);
    return x;
}

std::vector<uint8_t> make_header(const KdfParams& params,
                                 const std::array<uint8_t, kSaltLen>& salt,
                                 const std::array<uint8_t, kNonceLen>& nonce) {
    std::vector<uint8_t> h;
    h.insert(h.end(), kMagic, kMagic + 4);
    h.push_back(kVersion);
    put_u64(h, params.opslimit);
    put_u64(h, params.memlimit);
    h.insert(h.end(), salt.begin(), salt.end());
    h.insert(h.end(), nonce.begin(), nonce.end());
    return h;
}

}  // namespace

Result<Session> Session::create(const std::filesystem::path& file,
                                const std::string& master_password,
                                KdfParams params) {
    if (std::filesystem::exists(file))
        return Result<Session>::failure(Err::Io, "vault already exists: " + file.string());
    if (master_password.size() < 8)
        return Result<Session>::failure(Err::BadArgs,
                                        "master password must be at least 8 characters");
    std::error_code ec;
    if (file.has_parent_path()) std::filesystem::create_directories(file.parent_path(), ec);
    auto salt = random_salt();
    auto key = derive_key(master_password, salt, params);
    if (!key.ok()) return Result<Session>::failure(key.error.code, key.error.message);
    Session s(file, params, salt, std::move(*key.value), Vault{});
    auto st = s.save();
    if (!st.ok()) return Result<Session>::failure(st.error.code, st.error.message);
    return Result<Session>::success(std::move(s));
}

Result<Session> Session::open(const std::filesystem::path& file,
                              const std::string& master_password) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return Result<Session>::failure(Err::Io, "cannot open " + file.string());
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    if (bytes.size() < kHeaderLen + 16)
        return Result<Session>::failure(Err::Corrupt, "vault file is truncated");
    if (std::memcmp(bytes.data(), kMagic, 4) != 0 || bytes[4] != kVersion)
        return Result<Session>::failure(Err::Corrupt,
                                        "not a KeyForge vault (bad magic or version)");
    KdfParams params{get_u64(&bytes[5]), get_u64(&bytes[13])};
    if (params.memlimit > (uint64_t(1) << 31) || params.opslimit > 64)
        return Result<Session>::failure(Err::Corrupt, "implausible KDF parameters in header");
    std::array<uint8_t, kSaltLen> salt{};
    std::memcpy(salt.data(), &bytes[21], kSaltLen);
    std::array<uint8_t, kNonceLen> nonce{};
    std::memcpy(nonce.data(), &bytes[37], kNonceLen);
    std::vector<uint8_t> header(bytes.begin(), bytes.begin() + kHeaderLen);
    std::vector<uint8_t> cipher(bytes.begin() + kHeaderLen, bytes.end());

    auto key = derive_key(master_password, salt, params);
    if (!key.ok()) return Result<Session>::failure(key.error.code, key.error.message);
    auto plain = aead_decrypt(*key.value, cipher, header, nonce);
    if (!plain.ok())
        return Result<Session>::failure(
            Err::WrongPassword,
            "Invalid master password (or vault file is corrupted). A previous version "
            "may exist at " + file.string() + ".bak");
    std::string json(reinterpret_cast<const char*>(plain.value->data()),
                     plain.value->size());
    auto vault = Vault::from_json(json);
    sodium_memzero(json.data(), json.size());
    if (!vault.ok()) return Result<Session>::failure(Err::Corrupt, vault.error.message);
    return Result<Session>::success(
        Session(file, params, salt, std::move(*key.value), std::move(*vault.value)));
}

Status Session::save() {
    std::string payload = vault_.to_json();
    auto nonce = random_nonce();
    auto header = make_header(params_, salt_, nonce);
    auto cipher = aead_encrypt(key_, reinterpret_cast<const uint8_t*>(payload.data()),
                               payload.size(), header, nonce);
    sodium_memzero(payload.data(), payload.size());

    auto tmp = std::filesystem::path(path_.string() + ".tmp");
    FILE* f = std::fopen(tmp.string().c_str(), "wb");
    if (!f) return Status::failure(Err::Io, "cannot write " + tmp.string());
    std::fwrite(header.data(), 1, header.size(), f);
    std::fwrite(cipher.data(), 1, cipher.size(), f);
    std::fflush(f);
#ifdef _WIN32
    _commit(_fileno(f));
#else
    fsync(fileno(f));
#endif
    std::fclose(f);

    std::error_code ec;
    if (std::filesystem::exists(path_)) {
        auto bak = std::filesystem::path(path_.string() + ".bak");
        std::filesystem::remove(bak, ec);
        ec.clear();
        std::filesystem::rename(path_, bak, ec);
        if (ec) return Status::failure(Err::Io, "could not create backup: " + ec.message());
    }
    std::filesystem::rename(tmp, path_, ec);
    if (ec) return Status::failure(Err::Io, "could not replace vault: " + ec.message());
    return Status::success();
}

Status Session::export_copy(const std::filesystem::path& dest) const {
    std::error_code ec;
    std::filesystem::copy_file(path_, dest,
                               std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) return Status::failure(Err::Io, "export failed: " + ec.message());
    return Status::success();
}

}  // namespace vaultcore
```

Add `src/storage.cpp` to `core/CMakeLists.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS. (This file's tests run several Argon2 derivations even at MIN params — a few seconds is normal.)

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: encrypted vault file with authenticated header, atomic saves, .bak"
```

---

### Task 5: Password generator

**Files:**
- Create: `core/include/vaultcore/generator.hpp`, `core/src/generator.cpp`, `tests/test_generator.cpp`
- Modify: `core/CMakeLists.txt`, `tests/CMakeLists.txt`

- [ ] **Step 1: Write the failing tests**

`tests/test_generator.cpp`:
```cpp
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
```

Add `test_generator.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/generator.hpp` not found.

- [ ] **Step 3: Implement**

`core/include/vaultcore/generator.hpp`:
```cpp
#pragma once
#include <string>
#include "result.hpp"

namespace vaultcore {

struct GenOptions {
    int length = 20;
    bool symbols = true;
    bool allow_ambiguous = false;  // when false, 0 O 1 l I are excluded
};

// CSPRNG-only generation; guarantees at least one char from every enabled class.
Result<std::string> generate_password(const GenOptions& opt);

}  // namespace vaultcore
```

`core/src/generator.cpp`:
```cpp
#include "vaultcore/generator.hpp"
#include <sodium.h>
#include <utility>
#include <vector>

namespace vaultcore {
namespace {
constexpr const char* kLowerSafe = "abcdefghijkmnopqrstuvwxyz";
constexpr const char* kLowerAll = "abcdefghijklmnopqrstuvwxyz";
constexpr const char* kUpperSafe = "ABCDEFGHJKLMNPQRSTUVWXYZ";
constexpr const char* kUpperAll = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr const char* kDigitSafe = "23456789";
constexpr const char* kDigitAll = "0123456789";
constexpr const char* kSymbols = "!@#$%^&*()-_=+[]{};:,.?";
}  // namespace

Result<std::string> generate_password(const GenOptions& opt) {
    if (opt.length < 4 || opt.length > 128)
        return Result<std::string>::failure(Err::BadArgs, "length must be between 4 and 128");
    std::vector<std::string> classes = {
        opt.allow_ambiguous ? kLowerAll : kLowerSafe,
        opt.allow_ambiguous ? kUpperAll : kUpperSafe,
        opt.allow_ambiguous ? kDigitAll : kDigitSafe};
    if (opt.symbols) classes.push_back(kSymbols);

    std::string all;
    for (const auto& c : classes) all += c;

    std::string out;
    for (const auto& c : classes)
        out += c[randombytes_uniform(uint32_t(c.size()))];
    while (int(out.size()) < opt.length)
        out += all[randombytes_uniform(uint32_t(all.size()))];
    // Fisher-Yates so the guaranteed class chars aren't stuck at the front.
    for (size_t i = out.size() - 1; i > 0; --i)
        std::swap(out[i], out[randombytes_uniform(uint32_t(i + 1))]);
    return Result<std::string>::success(std::move(out));
}

}  // namespace vaultcore
```

Add `src/generator.cpp` to `core/CMakeLists.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: CSPRNG password generator with class guarantees"
```

---

### Task 6: Base32 + TOTP (RFC 6238)

**Files:**
- Create: `core/include/vaultcore/totp.hpp`, `core/src/totp.cpp`, `tests/test_totp.cpp`
- Modify: `core/CMakeLists.txt`, `tests/CMakeLists.txt`

- [ ] **Step 1: Write the failing tests**

`tests/test_totp.cpp`:
```cpp
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
```

Add `test_totp.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/totp.hpp` not found.

- [ ] **Step 3: Implement**

`core/include/vaultcore/totp.hpp`:
```cpp
#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "result.hpp"

namespace vaultcore {

// RFC 4648 base32; case-insensitive; spaces, dashes and '=' padding ignored.
Result<std::vector<uint8_t>> base32_decode(std::string_view s);

// RFC 6238 TOTP with HMAC-SHA1 (the authenticator-app standard).
Result<std::string> totp_code(std::string_view base32_secret, int64_t unix_time,
                              int digits = 6, int period = 30);
int totp_seconds_remaining(int64_t unix_time, int period = 30);

struct OtpauthInfo {
    std::string secret;  // base32, validated
    int digits = 6;
    int period = 30;
    std::string label;
};
Result<OtpauthInfo> parse_otpauth_uri(const std::string& uri);  // implemented in Task 7

}  // namespace vaultcore
```

`core/src/totp.cpp`:
```cpp
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
```

Add `src/totp.cpp` to `core/CMakeLists.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS — all RFC vectors match.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: base32 and RFC 6238 TOTP with HMAC-SHA1"
```

---

### Task 7: otpauth:// URI parsing

**Files:**
- Create: `tests/test_otpauth.cpp`
- Modify: `core/src/totp.cpp` (append `parse_otpauth_uri` + `url_decode` helper), `tests/CMakeLists.txt`

- [ ] **Step 1: Write the failing tests**

`tests/test_otpauth.cpp`:
```cpp
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
```

Add `test_otpauth.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: LINK FAILURE — undefined symbol `parse_otpauth_uri` (declared in Task 6's header).

- [ ] **Step 3: Implement — append to `core/src/totp.cpp`** (inside `namespace vaultcore`, after `totp_seconds_remaining`; add `#include <sstream>` and `#include "vaultcore/util.hpp"` at the top, and add this helper inside the anonymous namespace):

```cpp
// In the anonymous namespace:
std::string url_decode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() &&
            std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            out += char(std::stoi(s.substr(i + 1, 2), nullptr, 16));
            i += 2;
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}
```

```cpp
// At namespace vaultcore scope:
Result<OtpauthInfo> parse_otpauth_uri(const std::string& uri) {
    const std::string prefix = "otpauth://totp/";
    if (uri.rfind(prefix, 0) != 0)
        return Result<OtpauthInfo>::failure(Err::BadUri, "not an otpauth://totp/ URI");
    OtpauthInfo info;
    auto qpos = uri.find('?');
    info.label = url_decode(uri.substr(
        prefix.size(), qpos == std::string::npos ? std::string::npos : qpos - prefix.size()));
    if (qpos == std::string::npos)
        return Result<OtpauthInfo>::failure(Err::BadUri, "missing '?secret=...' query");
    std::stringstream ss(uri.substr(qpos + 1));
    std::string kv;
    while (std::getline(ss, kv, '&')) {
        auto eq = kv.find('=');
        if (eq == std::string::npos) continue;
        std::string k = to_lower(kv.substr(0, eq));
        std::string val = url_decode(kv.substr(eq + 1));
        if (k == "secret") {
            info.secret = val;
        } else if (k == "digits") {
            try { info.digits = std::stoi(val); } catch (...) { info.digits = -1; }
            if (info.digits < 6 || info.digits > 8)
                return Result<OtpauthInfo>::failure(Err::BadUri, "digits must be 6-8");
        } else if (k == "period") {
            try { info.period = std::stoi(val); } catch (...) { info.period = -1; }
            if (info.period < 5 || info.period > 300)
                return Result<OtpauthInfo>::failure(Err::BadUri, "period must be 5-300");
        }
    }
    if (info.secret.empty())
        return Result<OtpauthInfo>::failure(Err::BadUri, "missing secret parameter");
    if (!base32_decode(info.secret).ok())
        return Result<OtpauthInfo>::failure(Err::BadUri, "secret is not valid base32");
    return Result<OtpauthInfo>::success(std::move(info));
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: otpauth:// URI parsing with validation"
```

---

### Task 8: QR image decoding (quirc + stb_image)

**Files:**
- Create: `core/include/vaultcore/qr.hpp`, `core/src/qr.cpp`, `tests/test_qr.cpp`, `tests/fixtures/totp_qr.png`, `tests/fixtures/not_a_qr.png`
- Modify: `core/CMakeLists.txt`, `tests/CMakeLists.txt`

- [ ] **Step 1: Generate test fixtures**

```bash
python3 -c "import qrcode" 2>/dev/null || python3 -m pip install --user "qrcode[pil]"
mkdir -p tests/fixtures
python3 -c "import qrcode; qrcode.make('otpauth://totp/KeyForge:demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=KeyForge').save('tests/fixtures/totp_qr.png')"
python3 -c "from PIL import Image; Image.new('RGB', (64, 64), (10, 12, 10)).save('tests/fixtures/not_a_qr.png')"
```

Expected: both PNG files exist under `tests/fixtures/`.

- [ ] **Step 2: Write the failing tests**

`tests/test_qr.cpp`:
```cpp
#include <doctest/doctest.h>
#include <vaultcore/qr.hpp>
#include <string>

using namespace vaultcore;

TEST_CASE("qr decoding") {
    SUBCASE("decodes an otpauth QR png") {
        auto r = decode_qr_image(std::string(TEST_FIXTURES_DIR) + "/totp_qr.png");
        REQUIRE(r.ok());
        CHECK(*r.value ==
              "otpauth://totp/KeyForge:demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
              "&issuer=KeyForge");
    }
    SUBCASE("image without a QR code fails with BadQr") {
        auto r = decode_qr_image(std::string(TEST_FIXTURES_DIR) + "/not_a_qr.png");
        REQUIRE_FALSE(r.ok());
        CHECK(r.error.code == Err::BadQr);
    }
    SUBCASE("missing file fails with Io") {
        auto r = decode_qr_image("/nonexistent/nope.png");
        REQUIRE_FALSE(r.ok());
        CHECK(r.error.code == Err::Io);
    }
}
```

Add `test_qr.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 3: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/qr.hpp` not found.

- [ ] **Step 4: Implement**

`core/include/vaultcore/qr.hpp`:
```cpp
#pragma once
#include <filesystem>
#include <string>
#include "result.hpp"

namespace vaultcore {

// Reads a PNG/JPG/etc image and returns the text payload of the first
// decodable QR code in it.
Result<std::string> decode_qr_image(const std::filesystem::path& image_path);

}  // namespace vaultcore
```

`core/src/qr.cpp`:
```cpp
#include "vaultcore/qr.hpp"
#include <quirc.h>
#include <cstring>

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_BMP
#include <stb_image.h>

namespace vaultcore {

Result<std::string> decode_qr_image(const std::filesystem::path& image_path) {
    int w = 0, h = 0, ch = 0;
    unsigned char* img = stbi_load(image_path.string().c_str(), &w, &h, &ch, 1);
    if (!img)
        return Result<std::string>::failure(Err::Io,
                                            "cannot read image: " + image_path.string());
    struct quirc* q = quirc_new();
    if (!q || quirc_resize(q, w, h) < 0) {
        stbi_image_free(img);
        if (q) quirc_destroy(q);
        return Result<std::string>::failure(Err::Io, "out of memory decoding QR");
    }
    uint8_t* buf = quirc_begin(q, nullptr, nullptr);
    std::memcpy(buf, img, size_t(w) * size_t(h));
    stbi_image_free(img);
    quirc_end(q);

    int n = quirc_count(q);
    for (int i = 0; i < n; ++i) {
        struct quirc_code code;
        struct quirc_data data;
        quirc_extract(q, i, &code);
        if (quirc_decode(&code, &data) == QUIRC_SUCCESS) {
            std::string payload(reinterpret_cast<char*>(data.payload),
                                size_t(data.payload_len));
            quirc_destroy(q);
            return Result<std::string>::success(std::move(payload));
        }
    }
    quirc_destroy(q);
    return Result<std::string>::failure(Err::BadQr, "no readable QR code found in image");
}

}  // namespace vaultcore
```

Add `src/qr.cpp` to `core/CMakeLists.txt`.

- [ ] **Step 5: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: QR image decoding for TOTP enrollment"
```

---

### Task 9: Vault health audit

**Files:**
- Create: `core/include/vaultcore/audit.hpp`, `core/src/audit.cpp`, `tests/test_audit.cpp`
- Modify: `core/CMakeLists.txt`, `tests/CMakeLists.txt`

- [ ] **Step 1: Write the failing tests**

`tests/test_audit.cpp`:
```cpp
#include <doctest/doctest.h>
#include <vaultcore/audit.hpp>
#include <vaultcore/vault.hpp>

using namespace vaultcore;

static void add(Vault& v, const std::string& name, const std::string& pw, int64_t t) {
    Entry e;
    e.name = name;
    e.password = pw;
    REQUIRE(v.add(e, t).ok());
}

TEST_CASE("audit") {
    constexpr int64_t kNow = 100'000'000;
    constexpr int64_t kTwoYearsAgo = kNow - 2 * 365LL * 24 * 3600;
    Vault v;
    add(v, "Weak", "abc123", kNow);                       // short + few classes
    add(v, "StrongA", "Xk9#mPq2$vLn8@Rw4Z", kNow);        // healthy
    add(v, "ReusedA", "Xy7$kQm3#pWn9@Lv2T", kNow);
    add(v, "ReusedB", "Xy7$kQm3#pWn9@Lv2T", kNow);
    add(v, "Old", "Qw8#nRt4$mKp7@Jx3Y", kTwoYearsAgo);

    auto findings = audit_vault(v, kNow);

    auto issues_for = [&](const std::string& name) {
        std::vector<std::string> out;
        for (const auto& f : findings)
            if (f.name == name) out.push_back(f.issue);
        return out;
    };

    CHECK(issues_for("Weak").size() == 1);
    CHECK(issues_for("StrongA").empty());
    CHECK(issues_for("ReusedA").size() == 1);
    CHECK(issues_for("ReusedB").size() == 1);
    CHECK(issues_for("Old").size() == 1);
    CHECK(issues_for("Old")[0].find("older") != std::string::npos);
}

TEST_CASE("audit of a healthy vault is empty") {
    Vault v;
    add(v, "A", "Xk9#mPq2$vLn8@Rw4Z", 100);
    CHECK(audit_vault(v, 200).empty());
}
```

Add `test_audit.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/audit.hpp` not found.

- [ ] **Step 3: Implement**

`core/include/vaultcore/audit.hpp`:
```cpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "vault.hpp"

namespace vaultcore {

struct AuditFinding {
    std::string name;   // entry name
    std::string issue;  // human-readable description
};

// Flags weak (<12 chars or <3 character classes), reused (identical password
// across entries), and old (password unchanged for >1 year) passwords.
std::vector<AuditFinding> audit_vault(const Vault& v, int64_t now);

}  // namespace vaultcore
```

`core/src/audit.cpp`:
```cpp
#include "vaultcore/audit.hpp"
#include <cctype>
#include <map>

namespace vaultcore {

std::vector<AuditFinding> audit_vault(const Vault& v, int64_t now) {
    std::vector<AuditFinding> out;

    for (const auto& e : v.entries()) {
        bool lo = false, up = false, di = false, sy = false;
        for (unsigned char c : e.password) {
            if (std::islower(c)) lo = true;
            else if (std::isupper(c)) up = true;
            else if (std::isdigit(c)) di = true;
            else sy = true;
        }
        int classes = int(lo) + int(up) + int(di) + int(sy);
        if (e.password.size() < 12 || classes < 3)
            out.push_back({e.name, "weak password (" + std::to_string(e.password.size()) +
                                       " chars, " + std::to_string(classes) +
                                       " character classes)"});
    }

    std::map<std::string, std::vector<std::string>> by_pw;
    for (const auto& e : v.entries())
        if (!e.password.empty()) by_pw[e.password].push_back(e.name);
    for (const auto& [pw, names] : by_pw)
        if (names.size() > 1)
            for (const auto& n : names)
                out.push_back({n, "password reused across " +
                                      std::to_string(names.size()) + " entries"});

    constexpr int64_t kYear = 365LL * 24 * 3600;
    for (const auto& e : v.entries()) {
        int64_t ref = e.password_changed_at ? e.password_changed_at : e.created_at;
        if (ref && now - ref > kYear)
            out.push_back({e.name, "password older than 1 year"});
    }
    return out;
}

}  // namespace vaultcore
```

Add `src/audit.cpp` to `core/CMakeLists.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: vault health audit (weak/reused/old passwords)"
```

---

### Task 10: CSV import

**Files:**
- Create: `core/include/vaultcore/porting.hpp`, `core/src/porting.cpp`, `tests/test_porting.cpp`
- Modify: `core/CMakeLists.txt`, `tests/CMakeLists.txt`

- [ ] **Step 1: Write the failing tests**

`tests/test_porting.cpp`:
```cpp
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
```

Add `test_porting.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/porting.hpp` not found.

- [ ] **Step 3: Implement**

`core/include/vaultcore/porting.hpp`:
```cpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "result.hpp"
#include "vault.hpp"

namespace vaultcore {

struct ImportReport {
    int imported = 0;
    std::vector<std::string> skipped;  // "row N: reason"
};

// Imports Chrome-style (name,url,username,password,notes/note) or
// Bitwarden-style (name,login_uri,login_username,login_password,notes) CSV.
// Valid rows are applied; malformed/duplicate rows are skipped and reported.
Result<ImportReport> import_csv(Vault& v, const std::string& csv_text, int64_t now);

}  // namespace vaultcore
```

`core/src/porting.cpp`:
```cpp
#include "vaultcore/porting.hpp"
#include "vaultcore/util.hpp"
#include <initializer_list>
#include <map>

namespace vaultcore {
namespace {

// RFC 4180-ish: quoted fields, "" escapes, newlines inside quotes.
std::vector<std::vector<std::string>> parse_csv(const std::string& text) {
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> row;
    std::string field;
    bool in_quotes = false;
    bool field_started = false;
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < text.size() && text[i + 1] == '"') { field += '"'; ++i; }
                else in_quotes = false;
            } else field += c;
        } else if (c == '"') {
            in_quotes = true;
            field_started = true;
        } else if (c == ',') {
            row.push_back(field);
            field.clear();
            field_started = false;
        } else if (c == '\n' || c == '\r') {
            if (c == '\r' && i + 1 < text.size() && text[i + 1] == '\n') ++i;
            if (!row.empty() || !field.empty() || field_started) {
                row.push_back(field);
                field.clear();
                field_started = false;
                rows.push_back(row);
                row.clear();
            }
        } else {
            field += c;
            field_started = true;
        }
    }
    if (!row.empty() || !field.empty() || field_started) {
        row.push_back(field);
        rows.push_back(row);
    }
    return rows;
}

}  // namespace

Result<ImportReport> import_csv(Vault& v, const std::string& csv_text, int64_t now) {
    auto rows = parse_csv(csv_text);
    if (rows.size() < 2)
        return Result<ImportReport>::failure(Err::BadCsv, "CSV has no data rows");

    std::map<std::string, size_t> col;
    for (size_t j = 0; j < rows[0].size(); ++j) col[to_lower(rows[0][j])] = j;
    auto pick = [&](const std::vector<std::string>& row,
                    std::initializer_list<const char*> names) -> std::string {
        for (const char* n : names) {
            auto it = col.find(n);
            if (it != col.end() && it->second < row.size()) return row[it->second];
        }
        return "";
    };
    if (!col.count("name"))
        return Result<ImportReport>::failure(Err::BadCsv, "CSV needs a 'name' column");
    if (!col.count("password") && !col.count("login_password"))
        return Result<ImportReport>::failure(
            Err::BadCsv, "CSV needs a 'password' (or 'login_password') column");

    ImportReport rep;
    for (size_t i = 1; i < rows.size(); ++i) {
        Entry e;
        e.name = pick(rows[i], {"name"});
        e.password = pick(rows[i], {"password", "login_password"});
        e.username = pick(rows[i], {"username", "login_username"});
        e.url = pick(rows[i], {"url", "login_uri"});
        e.notes = pick(rows[i], {"notes", "note"});
        if (e.name.empty()) {
            rep.skipped.push_back("row " + std::to_string(i + 1) + ": missing name");
            continue;
        }
        auto st = v.add(std::move(e), now);
        if (!st.ok()) {
            rep.skipped.push_back("row " + std::to_string(i + 1) + ": " + st.error.message);
            continue;
        }
        rep.imported++;
    }
    return Result<ImportReport>::success(std::move(rep));
}

}  // namespace vaultcore
```

Add `src/porting.cpp` to `core/CMakeLists.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: CSV import (Chrome/Bitwarden layouts) with per-row skip reasons"
```

---

### Task 11: Command tokenizer, usage text, suggestions

**Files:**
- Create: `core/include/vaultcore/commands.hpp`, `core/src/commands.cpp`, `tests/test_commands.cpp`
- Modify: `core/CMakeLists.txt`, `tests/CMakeLists.txt`

- [ ] **Step 1: Write the failing tests**

`tests/test_commands.cpp`:
```cpp
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
```

Add `test_commands.cpp` to `tests/CMakeLists.txt`.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j 2>&1 | tail -5`
Expected: compile FAILURE — `vaultcore/commands.hpp` not found.

- [ ] **Step 3: Implement**

`core/include/vaultcore/commands.hpp`:
```cpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "result.hpp"
#include "storage.hpp"
#include "vault.hpp"

namespace vaultcore {

struct CommandOutcome {
    enum class Kind { Text, EntryList, EntryDetail, Secret, Totp, Help };
    Kind kind = Kind::Text;
    bool ok = true;
    std::string message;           // status/error text (render red when !ok)
    std::vector<Entry> entries;    // EntryList rows / EntryDetail single entry
    std::string secret;            // Secret: generated/retrieved value; Totp: code
    std::string secret_label;      // e.g. "password for 'GitHub'"
    std::string totp_entry;        // Totp: entry name, for live refresh in the UI
    bool copy_to_clipboard = false;
    bool vault_changed = false;    // caller must Session::save() when true
    bool lock_requested = false;
};

// Splits a palette line into tokens; double quotes group words.
Result<std::vector<std::string>> tokenize(const std::string& line);

bool is_command_word(const std::string& word);
std::string usage_for(const std::string& command);  // "" if unknown
std::string help_text();

// Parses and runs one palette line against the unlocked session.
CommandOutcome execute_command(Session& session, const std::string& line, int64_t now);

}  // namespace vaultcore
```

`core/src/commands.cpp` (this task: everything EXCEPT `execute_command`, which is Task 12 — include a temporary stub so the file links):
```cpp
#include "vaultcore/commands.hpp"
#include "vaultcore/audit.hpp"
#include "vaultcore/generator.hpp"
#include "vaultcore/porting.hpp"
#include "vaultcore/qr.hpp"
#include "vaultcore/totp.hpp"
#include "vaultcore/util.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>

namespace vaultcore {
namespace {

const std::vector<std::string> kCommands = {
    "add", "audit", "delete", "export", "gen", "help", "import",
    "list", "lock", "retrieve", "show", "totp", "update"};

const std::set<std::string> kSwitches = {"--yes", "--no-symbols", "--allow-ambiguous"};

const std::map<std::string, std::string> kUsage = {
    {"add", "add <name> --password P [--username U] [--url U] [--notes N] "
            "[--tags t1,t2] [--totp-secret S | --totp-uri URI | --totp-qr PATH]"},
    {"audit", "audit"},
    {"delete", "delete <name> --yes"},
    {"export", "export <path>"},
    {"gen", "gen [--len N] [--no-symbols] [--allow-ambiguous]  (default: 20 chars, "
            "symbols on, ambiguous chars excluded -- meets the 12+/upper/digit/special "
            "recommendation)"},
    {"help", "help"},
    {"import", "import <path> [--format csv]"},
    {"list", "list [--tag filter]"},
    {"lock", "lock"},
    {"retrieve", "retrieve <name> [--type password|username|url|notes|totp]"},
    {"show", "show <name>"},
    {"totp", "totp <name>"},
    {"update", "update <name> [--username U] [--password P] [--url U] [--notes N] "
               "[--tags t1,t2] [--totp-secret S | --totp-uri URI | --totp-qr PATH]"},
};

struct ParsedArgs {
    std::vector<std::string> positional;
    std::map<std::string, std::string> flags;
    std::set<std::string> switches;
};

CommandOutcome fail(std::string msg) {
    CommandOutcome o;
    o.ok = false;
    o.message = std::move(msg);
    return o;
}

Result<ParsedArgs> parse_args(const std::vector<std::string>& tokens) {
    ParsedArgs a;
    for (size_t i = 1; i < tokens.size(); ++i) {
        const auto& t = tokens[i];
        if (t.rfind("--", 0) == 0) {
            if (kSwitches.count(t)) { a.switches.insert(t); continue; }
            if (i + 1 >= tokens.size())
                return Result<ParsedArgs>::failure(Err::BadArgs, "flag " + t + " needs a value");
            a.flags[t] = tokens[++i];
        } else {
            a.positional.push_back(t);
        }
    }
    return Result<ParsedArgs>::success(std::move(a));
}

int levenshtein(const std::string& a, const std::string& b) {
    std::vector<int> prev(b.size() + 1), cur(b.size() + 1);
    for (size_t j = 0; j <= b.size(); ++j) prev[j] = int(j);
    for (size_t i = 1; i <= a.size(); ++i) {
        cur[0] = int(i);
        for (size_t j = 1; j <= b.size(); ++j) {
            int sub = prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1);
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, sub});
        }
        std::swap(prev, cur);
    }
    return prev[b.size()];
}

std::vector<std::string> split_tags(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    std::stringstream ss(s);
    while (std::getline(ss, cur, ',')) {
        size_t b = cur.find_first_not_of(" \t");
        size_t e = cur.find_last_not_of(" \t");
        if (b != std::string::npos) out.push_back(cur.substr(b, e - b + 1));
    }
    return out;
}

Result<int> parse_int(const std::string& s) {
    try {
        size_t pos = 0;
        int v = std::stoi(s, &pos);
        if (pos != s.size())
            return Result<int>::failure(Err::BadArgs, "'" + s + "' is not a number");
        return Result<int>::success(v);
    } catch (...) {
        return Result<int>::failure(Err::BadArgs, "'" + s + "' is not a number");
    }
}

// Resolves --totp-secret / --totp-uri / --totp-qr into a validated base32 secret.
// Outer Result = error handling; inner optional = "was any totp flag given?".
Result<std::optional<std::string>> resolve_totp_flags(const ParsedArgs& a) {
    using R = Result<std::optional<std::string>>;
    int given = int(a.flags.count("--totp-secret")) + int(a.flags.count("--totp-uri")) +
                int(a.flags.count("--totp-qr"));
    if (given == 0) return R::success(std::nullopt);
    if (given > 1)
        return R::failure(Err::BadArgs,
                          "use only one of --totp-secret / --totp-uri / --totp-qr");
    std::string secret;
    if (a.flags.count("--totp-secret")) {
        secret = a.flags.at("--totp-secret");
    } else if (a.flags.count("--totp-uri")) {
        auto info = parse_otpauth_uri(a.flags.at("--totp-uri"));
        if (!info.ok()) return R::failure(info.error.code, info.error.message);
        secret = info.value->secret;
    } else {
        auto payload = decode_qr_image(a.flags.at("--totp-qr"));
        if (!payload.ok()) return R::failure(payload.error.code, payload.error.message);
        auto info = parse_otpauth_uri(*payload.value);
        if (!info.ok()) return R::failure(info.error.code, info.error.message);
        secret = info.value->secret;
    }
    if (!base32_decode(secret).ok())
        return R::failure(Err::BadBase32, "TOTP secret is not valid base32");
    return R::success(std::optional<std::string>(std::move(secret)));
}

}  // namespace

Result<std::vector<std::string>> tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quotes = false, has_token = false;
    for (char c : line) {
        if (in_quotes) {
            if (c == '"') in_quotes = false;
            else cur += c;
        } else if (c == '"') {
            in_quotes = true;
            has_token = true;
        } else if (std::isspace(static_cast<unsigned char>(c))) {
            if (has_token || !cur.empty()) {
                out.push_back(cur);
                cur.clear();
                has_token = false;
            }
        } else {
            cur += c;
            has_token = true;
        }
    }
    if (in_quotes)
        return Result<std::vector<std::string>>::failure(Err::BadArgs, "unclosed quote");
    if (has_token || !cur.empty()) out.push_back(cur);
    return Result<std::vector<std::string>>::success(std::move(out));
}

bool is_command_word(const std::string& word) {
    return kUsage.count(to_lower(word)) > 0;
}

std::string usage_for(const std::string& command) {
    auto it = kUsage.find(to_lower(command));
    return it == kUsage.end() ? std::string{} : it->second;
}

std::string help_text() {
    std::string out;
    for (const auto& c : kCommands) out += kUsage.at(c) + "\n\n";
    return out;
}

// Task 12 replaces this stub with the real dispatcher.
CommandOutcome execute_command(Session&, const std::string&, int64_t) {
    return fail("not implemented yet");
}

}  // namespace vaultcore
```

Add `src/commands.cpp` to `core/CMakeLists.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: palette tokenizer, usage text, command metadata"
```

---

### Task 12: Command dispatcher

**Files:**
- Modify: `core/src/commands.cpp` (replace the `execute_command` stub), `tests/test_commands.cpp` (append dispatcher tests)

- [ ] **Step 1: Write the failing tests — append to `tests/test_commands.cpp`**

```cpp
#include <vaultcore/crypto.hpp>
#include <vaultcore/storage.hpp>
#include <filesystem>
#include <fstream>

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
```

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build build -j && ./build/tests/core_tests 2>&1 | tail -5`
Expected: build OK, test FAILURES ("not implemented yet" from the stub).

- [ ] **Step 3: Implement — replace the `execute_command` stub in `core/src/commands.cpp` with:**

```cpp
CommandOutcome execute_command(Session& session, const std::string& line, int64_t now) {
    using Kind = CommandOutcome::Kind;
    auto toks = tokenize(line);
    if (!toks.ok()) return fail(toks.error.message);
    if (toks.value->empty()) return fail("type a command — try 'help'");
    const std::string cmd = to_lower((*toks.value)[0]);
    if (!is_command_word(cmd)) {
        std::string best;
        int bestd = 3;
        for (const auto& c : kCommands) {
            int d = levenshtein(cmd, c);
            if (d < bestd) { bestd = d; best = c; }
        }
        std::string msg = "unknown command '" + cmd + "'";
        if (!best.empty()) msg += " — did you mean '" + best + "'?";
        return fail(msg);
    }
    auto parsed = parse_args(*toks.value);
    if (!parsed.ok()) return fail(parsed.error.message);
    const ParsedArgs& a = *parsed.value;
    Vault& v = session.vault();
    CommandOutcome out;

    if (cmd == "help") {
        out.kind = Kind::Help;
        out.message = help_text();
        return out;
    }
    if (cmd == "lock") {
        out.lock_requested = true;
        out.message = "Vault locked.";
        return out;
    }
    if (cmd == "gen") {
        GenOptions o;
        o.length = v.settings().gen_len;
        o.symbols = v.settings().gen_symbols;
        if (a.flags.count("--len")) {
            auto n = parse_int(a.flags.at("--len"));
            if (!n.ok()) return fail(n.error.message);
            o.length = *n.value;
        }
        if (a.switches.count("--no-symbols")) o.symbols = false;
        if (a.switches.count("--allow-ambiguous")) o.allow_ambiguous = true;
        auto r = generate_password(o);
        if (!r.ok()) return fail(r.error.message);
        out.kind = Kind::Secret;
        out.secret = *r.value;
        out.secret_label = "generated password";
        out.message = "Generated " + std::to_string(o.length) + "-character password:";
        return out;
    }
    if (cmd == "list") {
        std::string tag = a.flags.count("--tag") ? a.flags.at("--tag") : "";
        out.kind = Kind::EntryList;
        for (const Entry* e : v.list(tag)) out.entries.push_back(*e);
        out.message = std::to_string(out.entries.size()) +
                      (tag.empty() ? " entries" : " entries tagged '" + tag + "'");
        return out;
    }
    if (cmd == "audit") {
        auto findings = audit_vault(v, now);
        if (findings.empty()) {
            out.message = "No issues found — vault is healthy.";
            return out;
        }
        out.message = std::to_string(findings.size()) + " finding(s):\n";
        for (const auto& f : findings) out.message += "  " + f.name + ": " + f.issue + "\n";
        return out;
    }

    // Everything below takes a <name> or <path> positional argument.
    if (a.positional.empty()) return fail("usage: " + kUsage.at(cmd));
    const std::string& arg0 = a.positional[0];

    if (cmd == "add") {
        if (!a.flags.count("--password"))
            return fail("add requires --password (tip: run 'gen' first)");
        auto totp = resolve_totp_flags(a);
        if (!totp.ok()) return fail(totp.error.message);
        Entry e;
        e.name = arg0;
        e.password = a.flags.at("--password");
        if (a.flags.count("--username")) e.username = a.flags.at("--username");
        if (a.flags.count("--url")) e.url = a.flags.at("--url");
        if (a.flags.count("--notes")) e.notes = a.flags.at("--notes");
        if (a.flags.count("--tags")) e.tags = split_tags(a.flags.at("--tags"));
        if (totp.value->has_value()) e.totp_secret = **totp.value;
        auto st = v.add(std::move(e), now);
        if (!st.ok()) return fail(st.error.message);
        out.vault_changed = true;
        out.message = "Added '" + arg0 + "'.";
        return out;
    }
    if (cmd == "update") {
        auto totp = resolve_totp_flags(a);
        if (!totp.ok()) return fail(totp.error.message);
        EntryPatch p;
        if (a.flags.count("--username")) p.username = a.flags.at("--username");
        if (a.flags.count("--password")) p.password = a.flags.at("--password");
        if (a.flags.count("--url")) p.url = a.flags.at("--url");
        if (a.flags.count("--notes")) p.notes = a.flags.at("--notes");
        if (a.flags.count("--tags")) p.tags = split_tags(a.flags.at("--tags"));
        if (totp.value->has_value()) p.totp_secret = **totp.value;
        auto st = v.update_entry(arg0, p, now);
        if (!st.ok()) return fail(st.error.message);
        out.vault_changed = true;
        out.message = "Updated '" + arg0 + "'.";
        return out;
    }
    if (cmd == "delete") {
        if (!a.switches.count("--yes"))
            return fail("refusing to delete '" + arg0 + "' without --yes");
        auto st = v.remove(arg0);
        if (!st.ok()) return fail(st.error.message);
        out.vault_changed = true;
        out.message = "Deleted '" + arg0 + "'.";
        return out;
    }
    if (cmd == "show") {
        const Entry* e = v.find(arg0);
        if (!e) return fail("no entry named '" + arg0 + "'");
        out.kind = Kind::EntryDetail;
        out.entries.push_back(*e);
        return out;
    }
    if (cmd == "retrieve") {
        const Entry* e = v.find(arg0);
        if (!e) return fail("no entry named '" + arg0 + "'");
        std::string type = a.flags.count("--type") ? to_lower(a.flags.at("--type"))
                                                   : "password";
        std::string value;
        if (type == "password") value = e->password;
        else if (type == "username") value = e->username;
        else if (type == "url") value = e->url;
        else if (type == "notes") value = e->notes;
        else if (type == "totp") {
            if (e->totp_secret.empty()) return fail("'" + arg0 + "' has no TOTP configured");
            auto code = totp_code(e->totp_secret, now);
            if (!code.ok()) return fail(code.error.message);
            value = *code.value;
        } else {
            return fail("unknown --type '" + type + "' (password|username|url|notes|totp)");
        }
        if (value.empty()) return fail("'" + arg0 + "' has no " + type);
        out.kind = Kind::Secret;
        out.secret = value;
        out.secret_label = type + " for '" + arg0 + "'";
        out.copy_to_clipboard = true;
        out.message = "Copied " + type + " for '" + arg0 + "' to clipboard.";
        return out;
    }
    if (cmd == "totp") {
        const Entry* e = v.find(arg0);
        if (!e) return fail("no entry named '" + arg0 + "'");
        if (e->totp_secret.empty()) return fail("'" + arg0 + "' has no TOTP configured");
        auto code = totp_code(e->totp_secret, now);
        if (!code.ok()) return fail(code.error.message);
        out.kind = Kind::Totp;
        out.secret = *code.value;
        out.totp_entry = e->name;
        out.message = "TOTP for '" + e->name + "'";
        return out;
    }
    if (cmd == "export") {
        auto st = session.save();
        if (!st.ok()) return fail(st.error.message);
        st = session.export_copy(arg0);
        if (!st.ok()) return fail(st.error.message);
        out.message = "Exported encrypted vault to " + arg0;
        return out;
    }
    if (cmd == "import") {
        std::string format = a.flags.count("--format") ? to_lower(a.flags.at("--format"))
                                                       : "csv";
        if (format != "csv") return fail("only --format csv is supported");
        std::ifstream in(arg0, std::ios::binary);
        if (!in) return fail("cannot read " + arg0);
        std::string text((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        auto report = import_csv(v, text, now);
        if (!report.ok()) return fail(report.error.message);
        out.vault_changed = report.value->imported > 0;
        out.message = "Imported " + std::to_string(report.value->imported) + " entries.";
        if (!report.value->skipped.empty()) {
            out.message += " Skipped " + std::to_string(report.value->skipped.size()) + ":\n";
            for (const auto& sk : report.value->skipped) out.message += "  " + sk + "\n";
        }
        return out;
    }
    return fail("unhandled command");  // unreachable: every kCommands entry is handled
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j && ./build/tests/core_tests`
Expected: SUCCESS — full core suite green.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: command dispatcher wiring all palette commands to the core"
```

---

### Task 13: GUI shell — window, theme, unlock screen

**Files:**
- Create: `app/CMakeLists.txt`, `app/src/main.cpp`, `app/src/theme.hpp`, `app/src/theme.cpp`, `app/src/app.hpp`, `app/src/app.cpp`
- Modify: root `CMakeLists.txt` (add `add_subdirectory(app)` after `add_subdirectory(core)`)

No unit tests — the shell is deliberately thin; verification is manual (Step 3).

- [ ] **Step 1: Write the GUI scaffolding**

Root `CMakeLists.txt`: add `add_subdirectory(app)` on the line after `add_subdirectory(core)`.

`app/CMakeLists.txt`:
```cmake
find_package(OpenGL REQUIRED)
add_executable(keyforge
  src/main.cpp
  src/app.cpp
  src/theme.cpp)
target_link_libraries(keyforge PRIVATE vaultcore imgui glfw OpenGL::GL)
target_compile_definitions(keyforge PRIVATE GL_SILENCE_DEPRECATION)
```

`app/src/theme.hpp`:
```cpp
#pragma once
namespace keyforge {
void apply_theme();  // dark green-on-black palette matching the reference design
inline constexpr float kErrRed[4] = {0.86f, 0.36f, 0.32f, 1.0f};
}  // namespace keyforge
```

`app/src/theme.cpp`:
```cpp
#include "theme.hpp"
#include <imgui.h>

namespace keyforge {

void apply_theme() {
    ImGuiStyle& st = ImGui::GetStyle();
    st.WindowRounding = 0.0f;
    st.FrameRounding = 3.0f;
    st.FrameBorderSize = 1.0f;
    st.WindowBorderSize = 0.0f;
    st.FramePadding = ImVec2(10, 8);
    st.ItemSpacing = ImVec2(10, 10);
    st.WindowPadding = ImVec2(16, 16);
    st.ScrollbarSize = 10.0f;

    const ImVec4 bg{0.043f, 0.055f, 0.047f, 1.0f};
    const ImVec4 panel{0.075f, 0.095f, 0.080f, 1.0f};
    const ImVec4 frame{0.030f, 0.042f, 0.034f, 1.0f};
    const ImVec4 text{0.60f, 0.80f, 0.63f, 1.0f};
    const ImVec4 dim{0.38f, 0.52f, 0.41f, 1.0f};
    const ImVec4 border{0.29f, 0.50f, 0.35f, 1.0f};
    const ImVec4 accent{0.36f, 0.62f, 0.43f, 1.0f};

    ImVec4* c = st.Colors;
    c[ImGuiCol_WindowBg] = bg;
    c[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg] = panel;
    c[ImGuiCol_Text] = text;
    c[ImGuiCol_TextDisabled] = dim;
    c[ImGuiCol_FrameBg] = frame;
    c[ImGuiCol_FrameBgHovered] = panel;
    c[ImGuiCol_FrameBgActive] = panel;
    c[ImGuiCol_Border] = border;
    c[ImGuiCol_Button] = frame;
    c[ImGuiCol_ButtonHovered] = panel;
    c[ImGuiCol_ButtonActive] = accent;
    c[ImGuiCol_TitleBg] = bg;
    c[ImGuiCol_TitleBgActive] = bg;
    c[ImGuiCol_TitleBgCollapsed] = bg;
    c[ImGuiCol_ScrollbarBg] = bg;
    c[ImGuiCol_ScrollbarGrab] = border;
    c[ImGuiCol_ScrollbarGrabHovered] = accent;
    c[ImGuiCol_ScrollbarGrabActive] = accent;
    c[ImGuiCol_Separator] = border;
    c[ImGuiCol_CheckMark] = accent;
    c[ImGuiCol_SliderGrab] = border;
    c[ImGuiCol_SliderGrabActive] = accent;
    c[ImGuiCol_PlotHistogram] = accent;
    c[ImGuiCol_TextSelectedBg] = ImVec4(0.36f, 0.62f, 0.43f, 0.35f);
    c[ImGuiCol_NavHighlight] = accent;
    c[ImGuiCol_HeaderHovered] = panel;
    c[ImGuiCol_HeaderActive] = panel;
    c[ImGuiCol_Header] = panel;
}

}  // namespace keyforge
```

`app/src/app.hpp`:
```cpp
#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vaultcore/commands.hpp>
#include <vaultcore/storage.hpp>

struct GLFWwindow;

namespace keyforge {

class App {
public:
    App(GLFWwindow* window, std::filesystem::path vault_path);
    void frame();  // call once per ImGui frame

private:
    enum class Screen { Unlock, Main };

    void draw_unlock();
    void draw_main();
    void draw_sidebar();
    void draw_palette();
    void draw_results();
    void draw_settings();
    void run_command(const std::string& line);
    void copy_secret(const std::string& value);
    void tick_timers();
    void lock();

    GLFWwindow* window_;
    std::filesystem::path vault_path_;
    Screen screen_ = Screen::Unlock;
    std::optional<vaultcore::Session> session_;

    char master_buf_[256] = {};
    char master_confirm_buf_[256] = {};
    char input_buf_[512] = {};
    std::string unlock_error_;

    vaultcore::CommandOutcome last_;
    bool has_result_ = false;
    bool reveal_password_ = false;
    bool show_settings_ = false;
    bool focus_input_ = true;
    bool want_lock_ = false;

    std::string clip_value_;      // last value we put on the clipboard
    double clip_deadline_ = 0.0;  // glfwGetTime() when it must be cleared
    double last_activity_ = 0.0;  // for auto-lock
};

}  // namespace keyforge
```

`app/src/app.cpp` (this task: unlock flow + placeholder main screen; Task 14 replaces `draw_main/draw_sidebar/draw_palette/draw_results/draw_settings` with the real UI and Task 15 completes the timers):
```cpp
#include "app.hpp"
#include "theme.hpp"
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <sodium.h>
#include <cstring>
#include <ctime>

namespace keyforge {

using vaultcore::Session;

App::App(GLFWwindow* window, std::filesystem::path vault_path)
    : window_(window), vault_path_(std::move(vault_path)) {}

void App::frame() {
    tick_timers();
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##root", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoBringToFrontOnFocus |
                     ImGuiWindowFlags_NoSavedSettings);
    if (screen_ == Screen::Unlock) draw_unlock();
    else draw_main();
    ImGui::End();
}

void App::draw_unlock() {
    const bool first_run = !std::filesystem::exists(vault_path_);
    const float w = 380.0f;
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - w) * 0.5f);
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() * 0.28f);
    ImGui::BeginGroup();
    ImGui::PushItemWidth(w);
    ImGui::Text("KeyForge");
    ImGui::TextDisabled("%s", vault_path_.string().c_str());
    ImGui::Spacing();
    if (first_run)
        ImGui::TextDisabled("No vault yet — choose a master password (8+ chars).");

    bool submit = ImGui::InputTextWithHint("##master", "master password", master_buf_,
                                           sizeof master_buf_,
                                           ImGuiInputTextFlags_Password |
                                               ImGuiInputTextFlags_EnterReturnsTrue);
    if (first_run)
        submit |= ImGui::InputTextWithHint("##confirm", "confirm master password",
                                           master_confirm_buf_, sizeof master_confirm_buf_,
                                           ImGuiInputTextFlags_Password |
                                               ImGuiInputTextFlags_EnterReturnsTrue);
    submit |= ImGui::Button(first_run ? "Create Vault" : "Unlock", ImVec2(w, 0));

    if (submit) {
        std::string pw(master_buf_);
        if (first_run && pw != std::string(master_confirm_buf_)) {
            unlock_error_ = "passwords do not match";
        } else {
            auto r = first_run ? Session::create(vault_path_, pw)
                               : Session::open(vault_path_, pw);
            if (r.ok()) {
                session_.emplace(std::move(*r.value));
                screen_ = Screen::Main;
                unlock_error_.clear();
                has_result_ = false;
                input_buf_[0] = '\0';
                focus_input_ = true;
                last_activity_ = glfwGetTime();
            } else {
                unlock_error_ = r.error.message;
            }
        }
        sodium_memzero(master_buf_, sizeof master_buf_);
        sodium_memzero(master_confirm_buf_, sizeof master_confirm_buf_);
    }
    if (!unlock_error_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(kErrRed[0], kErrRed[1], kErrRed[2], 1));
        ImGui::TextWrapped("%s", unlock_error_.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::PopItemWidth();
    ImGui::EndGroup();
}

// ---- Placeholders replaced in Task 14 ----
void App::draw_main() {
    ImGui::Text("Unlocked. %zu entries.", session_->vault().entries().size());
    if (ImGui::Button("lock")) want_lock_ = true;
}
void App::draw_sidebar() {}
void App::draw_palette() {}
void App::draw_results() {}
void App::draw_settings() {}
void App::run_command(const std::string&) {}
void App::copy_secret(const std::string& value) {
    glfwSetClipboardString(window_, value.c_str());
    clip_value_ = value;
    clip_deadline_ = glfwGetTime() +
                     (session_ ? session_->vault().settings().clip_clear_sec : 30);
}
// ------------------------------------------

void App::tick_timers() {
    if (want_lock_) {
        want_lock_ = false;
        lock();
    }
}

void App::lock() {
    session_.reset();  // SecureBuffer destructor wipes the key
    screen_ = Screen::Unlock;
    last_ = {};
    has_result_ = false;
    reveal_password_ = false;
    show_settings_ = false;
    input_buf_[0] = '\0';
    unlock_error_.clear();
    if (!clip_value_.empty()) {
        const char* cur = glfwGetClipboardString(window_);
        if (cur && clip_value_ == cur) glfwSetClipboardString(window_, "");
        clip_value_.clear();
    }
}

}  // namespace keyforge
```

`app/src/main.cpp`:
```cpp
#include "app.hpp"
#include "theme.hpp"
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>
#include <vaultcore/crypto.hpp>
#include <vaultcore/paths.hpp>
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    vaultcore::crypto_init();
    std::filesystem::path vault_path = vaultcore::default_vault_dir() / "vault.kfv";
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == "--vault" && i + 1 < argc) vault_path = argv[++i];

    if (!glfwInit()) {
        std::fprintf(stderr, "glfwInit failed\n");
        return 1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
    GLFWwindow* window = glfwCreateWindow(900, 680, "KeyForge", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;  // no imgui.ini litter
    keyforge::apply_theme();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    keyforge::App app(window, vault_path);
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        app.frame();
        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.03f, 0.04f, 0.03f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
```

- [ ] **Step 2: Build**

Run: `cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j`
Expected: builds `build/app/keyforge` with no errors.

- [ ] **Step 3: Manual verification**

Run: `./build/app/keyforge --vault /tmp/kf-manual.kfv`
Checklist:
- Dark green-on-black window opens titled "KeyForge".
- First run shows two password fields; mismatched passwords show a red error; a short password shows the "at least 8 characters" error.
- Creating with a valid password lands on "Unlocked. 0 entries."
- Quit, rerun: single password field; wrong password shows red "Invalid master password…"; correct one unlocks.
- "lock" button returns to the unlock screen.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: GUI shell with theme and unlock/create-vault flow"
```

---

### Task 14: GUI main screen — sidebar, palette, results rendering, settings

**Files:**
- Modify: `app/src/app.cpp` — replace everything between the `// ---- Placeholders replaced in Task 14 ----` and `// ------------------------------------------` markers with the code below, and add `#include <sstream>` and `#include <vaultcore/totp.hpp>` at the top.

- [ ] **Step 1: Implement the main screen**

```cpp
namespace {
void entry_row(const vaultcore::Entry& e) {
    ImGui::TextUnformatted(e.name.c_str());
    if (!e.username.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", e.username.c_str());
    }
    if (!e.tags.empty()) {
        std::string t = "[";
        for (size_t i = 0; i < e.tags.size(); ++i)
            t += (i ? ", " : "") + e.tags[i];
        t += "]";
        ImGui::SameLine();
        ImGui::TextDisabled("%s", t.c_str());
    }
}

void field_row(const char* label, const std::string& value) {
    ImGui::TextDisabled("%-10s", label);
    ImGui::SameLine();
    ImGui::TextWrapped("%s", value.empty() ? "-" : value.c_str());
}
}  // namespace

void App::draw_main() {
    draw_sidebar();
    ImGui::SameLine();
    ImGui::BeginGroup();
    draw_palette();
    draw_results();
    ImGui::EndGroup();
    if (show_settings_) draw_settings();
}

void App::draw_sidebar() {
    ImGui::BeginChild("##side", ImVec2(52, 0));
    ImGui::TextDisabled("</>");
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 76);
    if (ImGui::Button("cfg", ImVec2(38, 30))) show_settings_ = !show_settings_;
    if (ImGui::Button("lk", ImVec2(38, 30))) want_lock_ = true;
    ImGui::EndChild();
}

void App::draw_palette() {
    if (focus_input_) {
        ImGui::SetKeyboardFocusHere();
        focus_input_ = false;
    }
    ImGui::SetNextItemWidth(-1);
    bool entered = ImGui::InputTextWithHint(
        "##cmd", "Type a command or search entries…", input_buf_, sizeof input_buf_,
        ImGuiInputTextFlags_EnterReturnsTrue);
    if (entered && input_buf_[0] != '\0') {
        run_command(input_buf_);
        input_buf_[0] = '\0';
        focus_input_ = true;
    }
}

void App::draw_results() {
    ImGui::BeginChild("##results", ImVec2(0, 0));
    const std::string typed(input_buf_);

    if (!typed.empty()) {
        std::istringstream is(typed);
        std::string first;
        is >> first;
        std::string usage = vaultcore::usage_for(first);
        if (!usage.empty()) {
            ImGui::TextDisabled("%s", usage.c_str());  // live usage hint while typing
        } else {
            for (const auto* e : session_->vault().search(typed)) entry_row(*e);
        }
        ImGui::EndChild();
        return;
    }

    if (!has_result_) {  // idle: show the whole vault
        for (const auto* e : session_->vault().list()) entry_row(*e);
        ImGui::EndChild();
        return;
    }

    using Kind = vaultcore::CommandOutcome::Kind;
    if (!last_.ok) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(kErrRed[0], kErrRed[1], kErrRed[2], 1));
        ImGui::TextWrapped("%s", last_.message.c_str());
        ImGui::PopStyleColor();
        ImGui::EndChild();
        return;
    }

    switch (last_.kind) {
        case Kind::Text:
        case Kind::Help:
            ImGui::TextWrapped("%s", last_.message.c_str());
            break;
        case Kind::EntryList:
            ImGui::TextDisabled("%s", last_.message.c_str());
            ImGui::Separator();
            for (const auto& e : last_.entries) entry_row(e);
            break;
        case Kind::EntryDetail: {
            const auto& e = last_.entries[0];
            field_row("name", e.name);
            field_row("username", e.username);
            ImGui::TextDisabled("%-10s", "password");
            ImGui::SameLine();
            ImGui::TextUnformatted(reveal_password_ ? e.password.c_str() : "************");
            ImGui::SameLine();
            if (ImGui::SmallButton(reveal_password_ ? "hide" : "reveal"))
                reveal_password_ = !reveal_password_;
            field_row("url", e.url);
            field_row("notes", e.notes);
            std::string tags;
            for (size_t i = 0; i < e.tags.size(); ++i) tags += (i ? ", " : "") + e.tags[i];
            field_row("tags", tags);
            field_row("totp", e.totp_secret.empty() ? "-" : "configured");
            break;
        }
        case Kind::Secret:
            ImGui::TextWrapped("%s", last_.message.c_str());
            if (!last_.copy_to_clipboard) {  // gen: show value + copy button
                ImGui::TextUnformatted(last_.secret.c_str());
                if (ImGui::SmallButton("copy")) copy_secret(last_.secret);
            } else if (!clip_value_.empty()) {
                ImGui::TextDisabled("clipboard clears in %ds",
                                    int(clip_deadline_ - glfwGetTime()) + 1);
            }
            break;
        case Kind::Totp: {
            const auto* e = session_->vault().find(last_.totp_entry);
            if (!e || e->totp_secret.empty()) {
                ImGui::TextDisabled("entry no longer has TOTP");
                break;
            }
            int64_t t = int64_t(std::time(nullptr));
            auto code = vaultcore::totp_code(e->totp_secret, t);
            int rem = vaultcore::totp_seconds_remaining(t);
            ImGui::TextDisabled("TOTP for '%s'", e->name.c_str());
            ImGui::SetWindowFontScale(1.8f);
            ImGui::TextUnformatted(code.ok() ? code.value->c_str() : "error");
            ImGui::SetWindowFontScale(1.0f);
            ImGui::ProgressBar(float(rem) / 30.0f, ImVec2(220, 8), "");
            ImGui::SameLine();
            ImGui::TextDisabled("%ds", rem);
            if (code.ok() && ImGui::SmallButton("copy")) copy_secret(*code.value);
            break;
        }
    }
    ImGui::EndChild();
}

void App::draw_settings() {
    ImGui::SetNextWindowSize(ImVec2(440, 0), ImGuiCond_Appearing);
    if (ImGui::Begin("Settings", &show_settings_, ImGuiWindowFlags_NoCollapse)) {
        auto& s = session_->vault().settings();
        ImGui::SliderInt("Auto-lock (min)", &s.auto_lock_min, 1, 60);
        ImGui::SliderInt("Clipboard clear (sec)", &s.clip_clear_sec, 5, 120);
        ImGui::SliderInt("Generator length", &s.gen_len, 8, 64);
        ImGui::Checkbox("Generator symbols", &s.gen_symbols);
        ImGui::Separator();
        ImGui::TextDisabled("Vault: %s", vault_path_.string().c_str());
        ImGui::TextDisabled("Launch with --vault <path> to use another vault file.");
        if (ImGui::Button("Save settings")) {
            auto st = session_->save();
            if (!st.ok()) unlock_error_ = st.error.message;  // shown after next lock
        }
    }
    ImGui::End();
}

void App::run_command(const std::string& line) {
    reveal_password_ = false;
    auto out = vaultcore::execute_command(*session_, line, int64_t(std::time(nullptr)));
    if (out.vault_changed) {
        auto st = session_->save();
        if (!st.ok()) {
            out.ok = false;
            out.message += "\nWARNING: saving vault failed: " + st.error.message;
        }
    }
    if (out.copy_to_clipboard) copy_secret(out.secret);
    if (out.lock_requested) want_lock_ = true;
    last_ = std::move(out);
    has_result_ = true;
}

void App::copy_secret(const std::string& value) {
    glfwSetClipboardString(window_, value.c_str());
    clip_value_ = value;
    clip_deadline_ = glfwGetTime() +
                     (session_ ? session_->vault().settings().clip_clear_sec : 30);
}
```

- [ ] **Step 2: Build**

Run: `cmake --build build -j`
Expected: builds clean.

- [ ] **Step 3: Manual verification**

Run: `./build/app/keyforge --vault /tmp/kf-manual.kfv` (unlock with the Task 13 password)
Checklist:
- Idle screen lists entries; typing plain text live-filters them; typing `add ` shows the usage hint inline.
- `help` prints the full command reference (matches the design's help screenshot).
- `add GitHub --password test1234 --username naram --tags dev` → "Added 'GitHub'." and idle list shows it.
- `gen --len 24` shows a password + working copy button.
- `show GitHub` masks the password; reveal/hide toggles.
- `retrieve GitHub` puts the password on the clipboard (paste somewhere to confirm) and shows the countdown line.
- `totp` on an entry with `--totp-secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` shows a live 6-digit code with countdown bar.
- `delte GitHub` suggests "did you mean 'delete'?" in red.
- Settings (cfg button) sliders work; Save settings persists after relock+unlock.
- `lock` and the sidebar `lk` button both return to the unlock screen.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: main screen with sidebar, command palette, results, settings"
```

---

### Task 15: Timers (clipboard auto-clear, auto-lock), README, final verification

**Files:**
- Modify: `app/src/app.cpp` (replace `tick_timers`)
- Create: `README.md`

- [ ] **Step 1: Implement the timers — replace `App::tick_timers` in `app/src/app.cpp` with:**

```cpp
void App::tick_timers() {
    const double now = glfwGetTime();
    if (want_lock_) {
        want_lock_ = false;
        lock();
    }
    // Clear the clipboard once the deadline passes — but only if it still
    // holds our value (never stomp something the user copied since).
    if (!clip_value_.empty() && now > clip_deadline_) {
        const char* cur = glfwGetClipboardString(window_);
        if (cur && clip_value_ == cur) glfwSetClipboardString(window_, "");
        clip_value_.clear();
    }
    ImGuiIO& io = ImGui::GetIO();
    if (io.MouseDelta.x != 0.0f || io.MouseDelta.y != 0.0f ||
        ImGui::IsMouseClicked(0) || io.MouseWheel != 0.0f ||
        io.InputQueueCharacters.Size > 0)
        last_activity_ = now;
    if (session_ && session_->vault().settings().auto_lock_min > 0 &&
        now - last_activity_ > session_->vault().settings().auto_lock_min * 60.0)
        lock();
}
```

- [ ] **Step 2: Write `README.md`**

```markdown
# KeyForge

A Bitwarden-style password manager that runs entirely on your machine.
One encrypted file, no network, no accounts. C++20, Dear ImGui.

## Build

Needs CMake ≥ 3.24 and a C++20 compiler. All libraries are fetched
automatically on first configure (takes a few minutes).

    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j
    ./build/tests/core_tests        # run the test suite
    ./build/app/keyforge            # launch (add --vault <path> to override)

## Commands

Type into the palette. `help` shows this list in-app.

    add <name> --password P [--username U] [--url U] [--notes N] [--tags t1,t2]
               [--totp-secret S | --totp-uri URI | --totp-qr PATH]
    update <name> [same flags as add]
    delete <name> --yes
    show <name>                    field view, password masked
    retrieve <name> [--type password|username|url|notes|totp]   copies to clipboard
    totp <name>                    live 6-digit code
    list [--tag filter]
    gen [--len N] [--no-symbols] [--allow-ambiguous]
    audit                          weak / reused / old passwords
    export <path>                  encrypted vault backup
    import <path> [--format csv]   Chrome/Bitwarden CSV
    lock
    help

Typing anything else searches your entries live.

## Security model

- Vault file: `KFV1` header (Argon2id opslimit/memlimit, salt, nonce) +
  XChaCha20-Poly1305 ciphertext of a JSON payload. The header is
  authenticated data — any tampering, even with KDF params, fails decryption.
- Master password → Argon2id (libsodium MODERATE) → 256-bit key.
- Saves are atomic (tmp + fsync + rename); the previous version is kept
  as `vault.kfv.bak`.
- The key lives in `sodium_malloc` locked memory and is wiped on lock/exit;
  the master-password input buffer is zeroed after use. Decrypted entry
  data lives in ordinary process memory while unlocked — locking drops it.
  Full locked-memory entry storage is out of scope.
- Clipboard auto-clears (default 30 s) only if it still holds our value.
- Auto-lock after idle (default 5 min), manual `lock`, lock on exit.

Default vault location: `~/Library/Application Support/keyforge/vault.kfv`
(macOS), `%APPDATA%\keyforge` (Windows), `~/.local/share/keyforge` (Linux).
```

- [ ] **Step 3: Full verification**

Run: `cmake --build build -j && ./build/tests/core_tests && ./build/app/keyforge --vault /tmp/kf-final.kfv`
Checklist:
- Full test suite green.
- Create a fresh vault; `add` two entries; `retrieve` one; wait past the clipboard timeout (set it to 5 s in settings) and confirm the clipboard empties.
- Set auto-lock to 1 minute, leave the app idle, confirm it returns to the unlock screen.
- `export /tmp/kf-backup.kfv`, then `./build/app/keyforge --vault /tmp/kf-backup.kfv` unlocks with the same master password and shows the same entries.
- `import` a small CSV and confirm the entries appear.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: clipboard auto-clear, idle auto-lock, README"
```

---

## Requirement → Task Traceability

| Spec requirement | Task |
|---|---|
| Vault format, Argon2id + XChaCha20-Poly1305, AAD header | 2, 4 |
| Atomic saves + .bak | 4 |
| Memory hygiene (locked key, wiped buffers) | 2, 4, 13 |
| Entry model, CRUD, tags, search, settings | 3 |
| add/update/delete/show/list/help | 11, 12 |
| retrieve + clipboard auto-clear | 12, 14, 15 |
| gen (defaults, flags, class guarantees) | 5, 12 |
| TOTP: secret/URI/QR, live code | 6, 7, 8, 12, 14 |
| audit | 9, 12 |
| import CSV / export encrypted copy | 10, 4, 12 |
| lock command, auto-lock, lock button | 12, 13, 15 |
| Unlock/create screens, palette UI, settings pane, theme | 13, 14 |
| App-data default + --vault override | 1, 13 |
| Error messages (wrong password, suggestions, typed errors) | 4, 11, 12 |
| Test coverage per spec | every core task |
