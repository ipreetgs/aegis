"""Tests for `aegis init` one-command setup (schema + feed auto-discovery/ingest).

Run:  python test_bootstrap.py
"""
import gzip
import json
import os
import tempfile
from pathlib import Path

from aegis.bootstrap import discover, run_init
from aegis.db.store import Store


def test_discover_finds_each_feed():
    d = Path(tempfile.mkdtemp(prefix="aegis-feeds-"))
    (d / "nvdcve-2024.json").write_text("{}")
    (d / "osv").mkdir()
    (d / "osv" / "x.json").write_text("{}")
    (d / "exploitdb").mkdir()
    (d / "modules_metadata_base.json").write_text("{}")
    (d / "ghdb.json").write_text("{}")
    (d / "epss_scores-2024-01-01.csv.gz").write_text("")
    (d / "known_exploited_vulnerabilities.json").write_text("{}")
    found = discover(str(d))
    for feed in ("nvd", "osv", "exploitdb", "msf", "ghdb", "epss", "kev"):
        assert found[feed], f"{feed} not discovered"
    print("✓ discover() finds all seven feed types by convention")


def test_discover_empty_dir():
    d = tempfile.mkdtemp(prefix="aegis-empty-")
    found = discover(d)
    assert all(v is None for v in found.values())
    print("✓ discover() on an empty dir finds nothing")


def test_init_empty_is_ready_with_no_feeds():
    store = Store(":memory:")
    summary = run_init(store, tempfile.mkdtemp(prefix="aegis-empty2-"))
    # schema exists → a correlation query runs without error
    assert store.evidence_for_cves(["CVE-0000-0000"])["cves_known"] == []
    assert summary["total_records"] == 0
    assert all(r["status"] == "skipped" for r in summary["results"])
    print("✓ init with no feeds still produces a ready, queryable DB")


def _feeds_with_kev_epss() -> str:
    d = Path(tempfile.mkdtemp(prefix="aegis-feeds2-"))
    (d / "known_exploited_vulnerabilities.json").write_text(json.dumps(
        {"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2019-11324"}]}))
    with gzip.open(d / "epss_scores-2024-01-01.csv.gz", "wt", encoding="utf-8") as fh:
        fh.write("#model_version\ncve,epss,percentile\nCVE-2021-44228,0.97,0.99\n")
    return str(d)


def test_init_ingests_discovered_feeds_and_is_idempotent():
    feeds = _feeds_with_kev_epss()
    store = Store(":memory:")
    summary = run_init(store, feeds)
    by = {r["feed"]: r for r in summary["results"]}
    assert by["kev"]["status"] == "ok" and by["kev"]["records"] == 2, by["kev"]
    assert by["epss"]["status"] == "ok" and by["epss"]["records"] == 1, by["epss"]
    assert by["nvd"]["status"] == "skipped"
    assert summary["feeds_loaded"] == 2 and summary["total_records"] == 3
    # idempotent: a second run over the same snapshots succeeds the same way
    again = run_init(store, feeds)
    assert again["total_records"] == 3
    print("✓ init ingests discovered feeds (kev+epss) and is idempotent")


def test_env_var_feeds_dir():
    feeds = _feeds_with_kev_epss()
    old = os.environ.get("AEGIS_FEEDS_DIR")
    os.environ["AEGIS_FEEDS_DIR"] = feeds
    try:
        summary = run_init(Store(":memory:"), None)
        assert summary["feeds_dir"] == feeds and summary["total_records"] == 3
    finally:
        if old is None:
            os.environ.pop("AEGIS_FEEDS_DIR", None)
        else:
            os.environ["AEGIS_FEEDS_DIR"] = old
    print("✓ init honours $AEGIS_FEEDS_DIR")


def main():
    test_discover_finds_each_feed()
    test_discover_empty_dir()
    test_init_empty_is_ready_with_no_feeds()
    test_init_ingests_discovered_feeds_and_is_idempotent()
    test_env_var_feeds_dir()
    print("\nALL BOOTSTRAP TESTS PASSED")


if __name__ == "__main__":
    main()
