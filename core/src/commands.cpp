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

}  // namespace vaultcore
