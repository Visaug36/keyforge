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
