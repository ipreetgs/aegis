"""Integration tests for the netsurvey + vulnsurvey wiring into aegis.

Proves, with no network feeds and no external tools:
  • the vulnsurvey-backed --audit surface turns a project dir into aegis findings,
    scored and correlated against the local index;
  • a seeded Metasploit-module link makes a matching finding tagged
    exploit_available (metadata only — nothing is launched);
  • local AI triage works offline and carries the detection-only note;
  • the netsurvey discovery adapter is importable and scope-enforced;
  • URL audits reject out-of-scope hosts.

Run:  python -I test_integration.py
"""
import tempfile
from pathlib import Path

from aegis.ai_triage import local_triage, suggest_findings
from aegis.db.store import Store
from aegis.integrations import netsurvey_discovery as nd
from aegis.scanners import audit_scan


def seed(store: Store) -> None:
    store.init_schema()
    store.upsert_vuln({"id": "CVE-2022-28346", "source": "nvd",
                       "cvss_score": 9.8, "cvss_severity": "CRITICAL"})
    store.set_kev("CVE-2022-28346")
    store.conn.execute(
        "INSERT OR REPLACE INTO msf_module(fullname, rank, has_check, platforms) "
        "VALUES(?,?,?,?)",
        ("exploit/linux/http/django_sample", "excellent", 1, "linux"))
    store.link("CVE-2022-28346", "msf", "exploit/linux/http/django_sample")
    store.commit()


def project_dir() -> str:
    d = Path(tempfile.mkdtemp(prefix="aegis-int-"))
    (d / "requirements.txt").write_text("django==2.2.5\nwerkzeug==0.14.0\n")
    (d / "config.env").write_text(
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
    return str(d)


def test_project_audit_and_exploit_availability():
    store = Store(":memory:")
    seed(store)
    report = audit_scan.scan(store, project_dir(), set())
    assert report.mode == "project"
    layers = {f.layer for f in report.findings}
    assert "vulnerable-dependency" in layers, layers
    assert "exposed-secret" in layers, layers
    # The django finding carries CVE-2022-28346, which we seeded with an MSF link.
    django = [f for f in report.findings if "CVE-2022-28346" in f.cve_ids]
    assert django, "expected the django CVE finding"
    assert django[0].exploit_available is True
    assert "Metasploit" in django[0].detail or "intel" in django[0].detail.lower()
    assert all(f.score > 0 for f in report.findings)
    print(f"✓ project audit: {len(report.findings)} findings, layers={sorted(layers)}")


def test_local_triage_is_offline_and_detection_only():
    store = Store(":memory:")
    seed(store)
    findings = [
        {"id": "dep:x", "severity": "critical", "detail": "django affected",
         "cve_ids": ["CVE-2022-28346"], "score": 100.0},
        {"id": "sec:y", "severity": "high", "detail": "key exposed", "cve_ids": [], "score": 80.0},
    ]
    out = local_triage(findings, store)
    assert "does not run exploits" in out
    assert "exploit/linux/http/django_sample" in out   # MSF module named from the index
    assert "verify" in out.lower()
    # suggest_findings falls back to local when no API key is configured
    assert local_triage(findings, store) in suggest_findings(findings, store)
    print("✓ local triage: offline, names MSF module, detection-only note present")


def test_netsurvey_adapter_scope_and_smoke():
    assert nd.available() is True
    # Out-of-scope target yields nothing and never scans.
    findings, errors = nd.discover(["http://10.1.2.3/"], {"example.com"})
    assert findings == []
    # In-scope loopback returns a (list, list) without raising (content port-dependent).
    findings, errors = nd.discover(["http://127.0.0.1/"], {"127.0.0.1"})
    assert isinstance(findings, list) and isinstance(errors, list)
    print(f"✓ netsurvey adapter: scope enforced, loopback smoke ({len(findings)} findings)")


def test_url_audit_rejects_out_of_scope():
    store = Store(":memory:")
    store.init_schema()
    report = audit_scan.scan(store, "http://127.0.0.1:9/", {"example.com"})
    assert report.findings == []
    assert any("out of scope" in e.lower() for e in report.errors)
    print("✓ url audit: out-of-scope host rejected")


def main():
    test_project_audit_and_exploit_availability()
    test_local_triage_is_offline_and_detection_only()
    test_netsurvey_adapter_scope_and_smoke()
    test_url_audit_rejects_out_of_scope()
    print("\nALL INTEGRATION TESTS PASSED")


if __name__ == "__main__":
    main()
