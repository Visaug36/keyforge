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
