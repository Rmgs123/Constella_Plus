import importlib
import os
import sys


def import_app(tmpdir):
    # Ensure clean module reload with isolated state directory
    sys.modules.pop("app", None)
    os.environ["STATE_DIR"] = tmpdir
    os.environ["PUBLIC_ADDR"] = "127.0.0.1:4747"
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    return importlib.import_module("app")


def test_upsert_peer_deduplicates_empty_node(monkeypatch, tmp_path):
    app = import_app(str(tmp_path))
    # clean state
    app.state["peers"] = []
    app.peers.clear()

    addr = "10.0.0.2:4747"
    app.upsert_peer({"name": "seed", "addr": addr, "node_id": "", "last_seen": 0})
    app.upsert_peer({"name": "seed", "addr": addr, "node_id": "node-xyz", "last_seen": app.now_s()})
    # Late heartbeat without node_id should not create a duplicate ghost
    app.upsert_peer({"name": "seed", "addr": addr, "node_id": "", "last_seen": app.now_s()})

    peers = [p for p in app.peers_with_status() if p.get("addr") == addr]
    assert len(peers) == 1
    assert peers[0].get("node_id") == "node-xyz"
