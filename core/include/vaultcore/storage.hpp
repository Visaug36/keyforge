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
