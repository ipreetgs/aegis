"""Gate tests for the Metasploit verify/exploit runner.

These prove the safety properties WITHOUT launching anything (and with no
Metasploit installed): scope is enforced, a module is required, exploit mode
refuses in a non-interactive context, dry-run only plans, and execution is only
ever reached after confirmation and still needs a real msfconsole.

Run:  python test_verify.py
"""
from aegis.db.store import Store
from aegis.integrations import metasploit_runner as msf


def seeded_store() -> Store:
    s = Store(":memory:")
    s.init_schema()
    s.upsert_vuln({"id": "CVE-2021-44228", "source": "nvd",
                   "cvss_score": 10.0, "cvss_severity": "CRITICAL"})
    s.conn.execute("INSERT OR REPLACE INTO msf_module(fullname, rank, has_check, platforms) "
                   "VALUES(?,?,?,?)",
                   ("exploit/multi/http/log4shell_header_injection", "excellent", 1, "multi"))
    s.link("CVE-2021-44228", "msf", "exploit/multi/http/log4shell_header_injection")
    s.commit()
    return s


def test_scope_rejected():
    r = msf.run(None, "http://evil.example/", {"uat.local"}, modules=["exploit/x"])
    assert r.findings == []
    assert any("out of scope" in e.lower() for e in r.errors)
    print("✓ out-of-scope target rejected before anything is built or run")


def test_module_required():
    r = msf.run(None, "http://uat.local/", {"uat.local"})
    assert r.findings == []
    assert any("no module" in e.lower() for e in r.errors)
    print("✓ refuses without an explicit module/CVE")


def test_verify_needs_msfconsole():
    r = msf.run(None, "http://uat.local/", {"uat.local"},
                modules=["exploit/x"], msfconsole="/no/such/msfconsole")
    assert any("msfconsole not found" in e.lower() for e in r.errors)
    print("✓ verify gracefully reports when msfconsole is absent (nothing run)")


def test_exploit_refuses_without_tty():
    # No interactive TTY in a test runner → must refuse and execute nothing.
    r = msf.run(None, "http://uat.local:8080/", {"uat.local"},
                modules=["exploit/multi/http/x"], exploit=True)
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.result == "refused", f.result
    assert "not executed" in f.detail.lower()
    print("✓ exploit mode refuses in a non-interactive context (no launch)")


def test_dry_run_plans_only():
    r = msf.run(None, "http://uat.local:8080/", {"uat.local"},
                modules=["exploit/multi/http/x"], exploit=True, dry_run=True)
    f = r.findings[0]
    assert f.result == "planned"
    assert "use exploit/multi/http/x" in f.detail
    assert "set RHOSTS uat.local" in f.detail
    print("✓ dry-run prints a resource-script plan and executes nothing")


def test_exploit_single_module_only():
    r = msf.run(None, "http://uat.local/", {"uat.local"},
                modules=["exploit/a", "exploit/b"], exploit=True, dry_run=True)
    assert any("exactly one" in e.lower() for e in r.errors)
    print("✓ exploit mode rejects more than one module")


def test_confirmed_still_needs_real_msf():
    # Even a confirmed exploit (test-only flag) cannot run without a real msfconsole.
    r = msf.run(None, "http://uat.local/", {"uat.local"},
                modules=["exploit/x"], exploit=True, assume_confirmed=True,
                msfconsole="/no/such/msfconsole")
    assert any("msfconsole not found" in e.lower() for e in r.errors)
    assert all(f.result != "executed" for f in r.findings)
    print("✓ confirmed exploit still requires a real installed msfconsole")


def test_build_resource_shapes():
    chk = msf.build_resource("exploit/x", "10.0.0.5", 8080, mode="check")
    assert "check" in chk and "PAYLOAD" not in chk
    exp = msf.build_resource("exploit/x", "10.0.0.5", 8080, mode="exploit",
                             payload="cmd/unix/generic", lhost="10.0.0.1")
    assert "set PAYLOAD cmd/unix/generic" in exp and "exploit -z" in exp
    print("✓ check script carries no payload; exploit script is explicit")


def test_modules_for_cves():
    mods = msf.modules_for_cves(seeded_store(), ["CVE-2021-44228"])
    assert "exploit/multi/http/log4shell_header_injection" in mods
    print("✓ CVE→module resolution via the local index")


def main():
    test_scope_rejected()
    test_module_required()
    test_verify_needs_msfconsole()
    test_exploit_refuses_without_tty()
    test_dry_run_plans_only()
    test_exploit_single_module_only()
    test_confirmed_still_needs_real_msf()
    test_build_resource_shapes()
    test_modules_for_cves()
    print("\nALL VERIFY-GATE TESTS PASSED")


if __name__ == "__main__":
    main()
