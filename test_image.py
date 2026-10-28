"""Synthetic container-image test: dpkg + pip layer + whiteout handling."""
import io
import json
import os
import tarfile
import tempfile

from aegis.db.store import Store
from aegis.scanners import image_scan
from aegis.report import render


def layer_bytes(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


dpkg = (
    b"Package: openssl\nStatus: install ok installed\nVersion: 1.1.1f-1ubuntu2\n\n"
    b"Package: bash\nStatus: install ok installed\nVersion: 5.0-6ubuntu1\n"
)
osrel = b'PRETTY_NAME="Ubuntu 20.04.3 LTS"\n'
l0 = layer_bytes({"etc/os-release": osrel, "var/lib/dpkg/status": dpkg})
# second layer adds a vulnerable pip manifest + a whiteout (deletes a prior file)
l1 = layer_bytes({"var/lib/dpkg/.wh.old-cruft": b"", "app/requirements.txt": b"urllib3==1.24.1\n"})

img = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
with tarfile.open(img.name, "w") as t:
    for nm, data in {"layer0.tar": l0, "layer1.tar": l1}.items():
        info = tarfile.TarInfo(nm)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    man = json.dumps([{"Layers": ["layer0.tar", "layer1.tar"]}]).encode()
    info = tarfile.TarInfo("manifest.json")
    info.size = len(man)
    t.addfile(info, io.BytesIO(man))

store = Store(":memory:")
store.init_schema()
store.upsert_vuln({"id": "CVE-2022-0778", "source": "nvd", "cvss_score": 7.5, "cvss_severity": "HIGH"})
store.add_affected("CVE-2022-0778", ecosystem="debian", product="openssl",
                   introduced="0", fixed="1.1.1n", range_kind="semver")
store.upsert_vuln({"id": "CVE-2019-11324", "source": "osv", "cvss_score": 7.5, "cvss_severity": "HIGH"})
store.add_affected("CVE-2019-11324", ecosystem="pypi", product="urllib3",
                   introduced="0", fixed="1.24.2")
store.commit()

rep = image_scan.scan(store, img.name)
print("os:", rep.os_name, "| layers:", rep.layers, "| components:", rep.components)
doc = render.normalize("image", rep)
for f in doc["findings"]:
    print(" ", f["id"], f["component"], "->", f.get("priority"), f["score"])

assert any(f["id"] == "CVE-2022-0778" for f in doc["findings"]), "dpkg openssl CVE missed"
assert any(f["id"] == "CVE-2019-11324" for f in doc["findings"]), "layer pip CVE missed"
os.unlink(img.name)
print("IMAGE SCAN TEST PASSED")
