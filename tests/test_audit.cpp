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
