#!/usr/bin/env python3
"""Banc d'essai des scripts d'installation du client (CI).

Rend les gabarits server/install/* comme le ferait le serveur, publie les
binaires d'un artefact de CI sous forme d'archive de release (+ SHA256SUMS)
et sert le tout en HTTP local :

    python3 tests/install/serve-fixture.py <plateforme> <dossier-artefact> [port]

Les ancres de confiance sont factices : seule l'installation est testée
(la synchronisation de l'index échoue et le script le signale sans échouer).
"""
import base64
import hashlib
import http.server
import json
import pathlib
import shutil
import sys
import tempfile

platform, artifact = sys.argv[1], pathlib.Path(sys.argv[2])
port = int(sys.argv[3]) if len(sys.argv) > 3 else 8765
url = f"http://127.0.0.1:{port}"
repo = pathlib.Path(__file__).resolve().parents[2]

site = pathlib.Path(tempfile.mkdtemp(prefix="auxipak-site-"))
(site / "downloads").mkdir()
name = f"auxipak-v0.0.0-ci-{platform}"
src = next(p for p in artifact.rglob("*") if p.is_dir() and p.name == f"auxipak-{platform}")
stage = pathlib.Path(tempfile.mkdtemp()) / name
shutil.copytree(src, stage)
fmt = "zip" if platform.startswith("windows") else "gztar"
archive = pathlib.Path(shutil.make_archive(str(site / "downloads" / name), fmt, stage.parent, name))
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(site / "downloads" / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")

root = json.dumps({"signed": {"_type": "root"}, "signatures": []}).encode()
keys = json.dumps({"keys": []}).encode()
subst = {
    "@@AUXIPAK_URL@@": url,
    "@@ROOT_SHA256@@": hashlib.sha256(root).hexdigest(),
    "@@ROOT_JSON@@": root.decode(),
    "@@KEYS_JSON@@": keys.decode(),
    "@@ROOT_B64@@": base64.b64encode(root).decode(),
    "@@KEYS_B64@@": base64.b64encode(keys).decode(),
}
for tpl in (repo / "server" / "install").iterdir():
    text = tpl.read_text(encoding="utf-8")
    for k, v in subst.items():
        text = text.replace(k, v)
    assert "@@" not in text, tpl
    (site / tpl.name).write_bytes(text.encode("utf-8"))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(site), **kw)

    def guess_type(self, path):
        return "text/plain; charset=utf-8" if path.endswith((".sh", ".ps1", "SHA256SUMS")) else "application/octet-stream"

    def log_message(self, *a):
        pass


print(f"Banc d'essai servi sur {url} ({archive.name})", flush=True)
http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
