#!/usr/bin/env python3
"""Fresh LAN discovery, persistent PeerId, and symmetric mempool handshake test."""

import datetime
import json
import os
import re
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_P2P_IDENTITY_DIR",
        str(RUN_PARENT / f"p2p-identity-handshake-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_P2P_IDENTITY_BASE_PORT", "20800"))

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def peer_id(text):
    match = re.search(r"loaded persistent P2P identity peer=([^\s]+)", text)
    require(match is not None, "startup log has no persistent PeerId")
    return match.group(1)


def symmetric_mempool_exchange(left_label, right_label):
    left = log_text(left_label)
    right = log_text(right_label)
    if all(
        marker in text
        for text in (left, right)
        for marker in (
            "requesting mempool sync",
            "serving mempool sync request",
            "mempool sync response complete",
        )
    ):
        return True
    return False


def assert_clean(label, text):
    forbidden = (
        " ERROR ",
        "panicked",
        "mempool sync request failed",
        "max sub-streams reached",
        "Handshake failed: input error",
        "P2P block rejected",
    )
    failures = [line for line in text.splitlines() if any(item in line for item in forbidden)]
    require(not failures, f"{label} contains P2P failures: {failures[-10:]}")


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    for port in (BASE_PORT, BASE_PORT + 1, BASE_PORT + 10, BASE_PORT + 11):
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_P2P_IDENTITY_RUN").write_text(str(BASE) + "\n")

    binary_hash = live.sha256(live.NODE_BIN)
    print(f"[run] {BASE}", flush=True)
    print(f"[binary] sha256={binary_hash} size={live.NODE_BIN.stat().st_size}", flush=True)
    left = Node("node-a", BASE_PORT, BASE_PORT + 1, p2p_host="0.0.0.0")
    right = Node("node-b", BASE_PORT + 10, BASE_PORT + 11, p2p_host="0.0.0.0")
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": binary_hash,
        "binary_size": live.NODE_BIN.stat().st_size,
        "status": "running",
    }
    error = None
    try:
        # No --seed on either side: this phase must connect through LAN mDNS.
        left.start("01-a-fresh-no-seed")
        right.start("02-b-fresh-no-seed")
        live.wait_value(
            "fresh no-seed nodes discover each other",
            lambda: int(rpc(left.rpc_port, "getPeerCount")) >= 1
            and int(rpc(right.rpc_port, "getPeerCount")) >= 1,
            timeout=120,
        )
        live.wait_value(
            "fresh peers complete symmetric empty-mempool exchange",
            lambda: symmetric_mempool_exchange(
                "01-a-fresh-no-seed", "02-b-fresh-no-seed"
            ),
            timeout=60,
        )
        first_logs = {
            "a": log_text("01-a-fresh-no-seed"),
            "b": log_text("02-b-fresh-no-seed"),
        }
        first_ids = {name: peer_id(text) for name, text in first_logs.items()}
        require(first_ids["a"] != first_ids["b"], "two data dirs share one PeerId")
        first_hashes = {
            "a": live.sha256(left.data_dir / "p2p_identity.key"),
            "b": live.sha256(right.data_dir / "p2p_identity.key"),
        }
        right.stop()
        left.stop()

        # Restart again without seeds. Peer store/mDNS addresses now contain
        # durable /p2p IDs and must reconnect without identity mismatch.
        left.start("03-a-restart-no-seed")
        right.start("04-b-restart-no-seed")
        live.wait_value(
            "restarted no-seed nodes reconnect",
            lambda: int(rpc(left.rpc_port, "getPeerCount")) >= 1
            and int(rpc(right.rpc_port, "getPeerCount")) >= 1,
            timeout=120,
        )
        live.wait_value(
            "restarted peers complete symmetric empty-mempool exchange",
            lambda: symmetric_mempool_exchange(
                "03-a-restart-no-seed", "04-b-restart-no-seed"
            ),
            timeout=60,
        )
        second_logs = {
            "a": log_text("03-a-restart-no-seed"),
            "b": log_text("04-b-restart-no-seed"),
        }
        second_ids = {name: peer_id(text) for name, text in second_logs.items()}
        second_hashes = {
            "a": live.sha256(left.data_dir / "p2p_identity.key"),
            "b": live.sha256(right.data_dir / "p2p_identity.key"),
        }
        require(second_ids == first_ids, f"PeerId rotated across restart: {first_ids} -> {second_ids}")
        require(second_hashes == first_hashes, "identity file changed across restart")
        require(
            "mDNS: discovered LAN peer" in first_logs["a"] + first_logs["b"],
            "fresh no-seed connection has no mDNS discovery evidence",
        )
        for label, text in {**first_logs, "a-restart": second_logs["a"], "b-restart": second_logs["b"]}.items():
            assert_clean(label, text)

        summary.update(
            {
                "status": "passed",
                "peer_ids": first_ids,
                "identity_hashes": first_hashes,
                "fresh_mempool_exchange": True,
                "restart_mempool_exchange": True,
                "mdns_discovery": True,
            }
        )
        print("[PASS] persistent PeerId, LAN discovery, and symmetric mempool handshake", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        right.stop()
        left.stop()
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"[summary] {BASE / 'summary.json'}", flush=True)
    if error is not None:
        raise error


if __name__ == "__main__":
    main()
