"""End-to-end smoke test with synthetic data — no network, no external feeds.

Proves the core loop: seed the unified DB with a CVE + Exploit-DB + MSF links,
then run the code scanner over a tiny fixture tree and confirm correlation +
scoring + reporting produce the expected structured output.

Run:  python -I smoke_test.py
"""
import json
import tempfile
from pathlib import Path

from aegis.db.store import Store
from aegis.scanners import code_scan
from aegis.report import render
from aegis.version import compare, VersionRange
from aegis.cvss import score_from_vector


def seed(store: Store):
    store.init_schema()
    # a real-world-shaped record: Log4Shell
    store.upsert_vuln({
        "id": "CVE-2021-44228", "source": "nvd",
        "description": "Log4j JNDI RCE", "cvss_score": 10.0,
        "cvss_severity": "CRITICAL", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    })
    store.set_epss("CVE-2021-44228", 0.975, 0.999)
    store.set_kev("CVE-2021-44228")
    store.add_affected("CVE-2021-44228", ecosystem="maven", product="log4j-core",
                       introduced="2.0", fixed="2.15.0", range_kind="semver")
    # a pypi example for requirements.txt correlation
    store.upsert_vuln({"id": "CVE-2019-11324", "source": "osv",
                       "cvss_score": 7.5, "cvss_severity": "HIGH"})
    store.add_affected("CVE-2019-11324", ecosystem="pypi", product="urllib3",
                       introduced="0", fixed="1.24.2", range_kind="semver")
    # evidence links
    store.conn.execute("INSERT OR REPLACE INTO exploit(edb_id, file_path) VALUES(50592, '/opt/exploitdb/exploits/java/remote/50592.py')")
    store.link("CVE-2021-44228", "edb", 50592)
    store.link("CVE-2021-44228", "msf", "exploit/multi/http/log4shell_header_injection")
    store.commit()


def fixture_tree() -> str:
    d = Path(tempfile.mkdtemp(prefix="aegis-fix-"))
    (d / "requirements.txt").write_text("urllib3==1.24.1\nrequests==2.31.0\n")
    (d / "app.py").write_text(
        "import os, pickle\n"
        "API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
        "    return eval(cmd)\n"
        "data = pickle.loads(open('x','rb').read())\n"
    )
    (d / "pom-note.txt").write_text("uses log4j-core 2.14.1\n")  # not a manifest; ignored
    return str(d)


def main():
    # unit checks
    assert compare("2.14.1", "2.15.0") < 0
    assert VersionRange(introduced="2.0", fixed="2.15.0").contains("2.14.1")
    assert not VersionRange(introduced="2.0", fixed="2.15.0").contains("2.15.0")
    s, lbl = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert s == 10.0 and lbl == "CRITICAL", (s, lbl)
    print("✓ version + cvss unit checks")

    store = Store(":memory:")
    seed(store)
    root = fixture_tree()
    report = code_scan.scan(store, root)

    doc = render.normalize("code", report)
    kinds = {}
    for f in doc["findings"]:
        kinds[f["type"]] = kinds.get(f["type"], 0) + 1

    print(f"✓ scanned {report.scanned_files} files")
    print(f"✓ finding types: {kinds}")

    ids = {f["id"] for f in doc["findings"]}
    assert "CVE-2019-11324" in ids, "dependency CVE not correlated"
    assert "aws-access-key-id" in ids, "secret not caught"
    assert any(f["id"].startswith("py-") for f in doc["findings"]), "sink not caught"
    print("✓ correlation (urllib3==1.24.1 -> CVE-2019-11324), secret, and sink all fired")

    # show the top of the report the operator would see
    print(render.to_cli("code", report))
    print("SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
