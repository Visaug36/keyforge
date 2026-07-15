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
