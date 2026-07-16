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
