#pragma once
#include <filesystem>

namespace vaultcore {

// OS-standard per-user data dir for keyforge (created lazily by callers):
// macOS: ~/Library/Application Support/keyforge
// Linux: $XDG_DATA_HOME/keyforge or ~/.local/share/keyforge
// Windows: %APPDATA%/keyforge
std::filesystem::path default_vault_dir();

}  // namespace vaultcore
