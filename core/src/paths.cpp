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
