#!/usr/bin/env python3
"""Fresh bounded-mesh block propagation beyond GossipSub mesh_n_high."""

import datetime
import json
import os
import time
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_P2P_MESH_BLOCK_DIR",
        str(RUN_PARENT / f"p2p-mesh-block-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_P2P_MESH_BLOCK_BASE_PORT", "21400"))
PEER_COUNT = int(os.environ.get("NOID_LIVE_P2P_MESH_BLOCK_PEERS", "16"))
TARGET_HEIGHT = int(os.environ.get("NOID_LIVE_P2P_MESH_BLOCK_HEIGHT", "2"))

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def all_exact_at_least(miner, peers, target):
    tip = miner.info()
    height = int(tip["height"])
    if height < target:
        return False
    for peer in peers:
        other = peer.info()
        if int(other["height"]) != height or other["best_hash"] != tip["best_hash"]:
            return False
    return {"height": height, "hash": tip["best_hash"], "peers": len(peers)}


def all_headers_match(reference, peers, through_height):
    expected = [rpc(reference.rpc_port, "getBlockHeader", [height]) for height in range(through_height + 1)]
    if any(header is None for header in expected):
        return False
    for peer in peers:
        for height, header in enumerate(expected):
            actual = rpc(peer.rpc_port, "getBlockHeader", [height])
            if actual is None or actual["hash"] != header["hash"]:
                return False
    return [header["hash"] for header in expected]


def peer_mesh_ready(peers, minimum_connections):
    counts = [int(rpc(peer.rpc_port, "getPeerCount")) for peer in peers]
    if all(count >= minimum_connections for count in counts):
        return {"minimum": min(counts), "maximum": max(counts)}
    return False


def assert_clean(label, text):
    forbidden = (
        " ERROR ",
        "panicked",
        "P2P network error",
        "max sub-streams reached",
        "Handshake failed: input error",
        "mempool sync request failed — retry limit reached",
        "P2P block rejected",
        "block sync request failed",
    )
    failures = [line for line in text.splitlines() if any(marker in line for marker in forbidden)]
    require(not failures, f"{label} contains failures: {failures[-10:]}")


def stop_peers(peers):
    errors = []
    for peer in peers:
        try:
            peer.request_stop()
        except Exception as error:
            errors.append(f"request {peer.name}: {error}")
    for peer in peers:
        try:
            peer.finish_stop()
        except Exception as error:
            errors.append(f"finish {peer.name}: {error}")
    return errors


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(9 <= PEER_COUNT <= 64, "mesh scenario must exceed mesh_n_high and remain local")
    require(TARGET_HEIGHT >= 1, "target height must be positive")
    require(not BASE.exists(), f"run directory already exists: {BASE}")

    # mDNS advertises LAN addresses, so listeners must not be loopback-only.
    # Explicit bootstrap still uses 127.0.0.1 through Node.seed.
    hub = Node("hub-miner", BASE_PORT, BASE_PORT + 1, p2p_host="0.0.0.0")
    peers = [
        Node(
            f"peer-{index:02d}",
            BASE_PORT + 100 + index * 2,
            BASE_PORT + 101 + index * 2,
            p2p_host="0.0.0.0",
        )
        for index in range(PEER_COUNT)
    ]
    for node in (hub, *peers):
        require(live.port_is_free(node.p2p_port), f"port occupied: {node.p2p_port}")
        require(live.port_is_free(node.rpc_port), f"port occupied: {node.rpc_port}")

    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_P2P_MESH_BLOCK_RUN").write_text(str(BASE) + "\n")
    binary_hash = live.sha256(live.NODE_BIN)
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={binary_hash} size={live.NODE_BIN.stat().st_size} peers={PEER_COUNT}",
        flush=True,
    )
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": binary_hash,
        "binary_size": live.NODE_BIN.stat().st_size,
        "peer_count": PEER_COUNT,
        "target_height": TARGET_HEIGHT,
        "status": "running",
    }
    error = None
    cleanup_errors = []
    bootstrap_label = "01-hub-fresh-genesis-node"
    peer_labels = [f"02-peer-{index:02d}-fresh" for index in range(PEER_COUNT)]
    miner_label = "03-hub-restarts-as-miner"
    try:
        hub.start(bootstrap_label, genesis=True)
        starts = [
            peer.spawn(label, seeds=[hub.seed])
            for peer, label in zip(peers, peer_labels)
        ]
        for peer, label, started in zip(peers, peer_labels, starts):
            peer.wait_ready(label, started)

        live.wait_value(
            "bootstrap hub accepts every peer",
            lambda: int(rpc(hub.rpc_port, "getPeerCount")) >= PEER_COUNT,
            timeout=120,
        )
        initial_mesh = live.wait_value(
            "every peer establishes direct non-hub connections",
            lambda: peer_mesh_ready(peers, 4),
            timeout=120,
        )
        identity_hash = live.sha256(hub.data_dir / "p2p_identity.key")
        hub.stop()

        hubless_mesh = live.wait_value(
            "peer mesh remains connected while the bootstrap hub is offline",
            lambda: peer_mesh_ready(peers, 2),
            timeout=120,
        )

        # The same durable PeerId returns in miner mode. Existing peers must
        # reconnect while fresh blocks are being produced.
        hub.start(miner_label, mode="miner")
        require(
            live.sha256(hub.data_dir / "p2p_identity.key") == identity_hash,
            "hub identity changed across miner restart",
        )
        live.wait_value(
            "all peers reconnect to active miner",
            lambda: int(rpc(hub.rpc_port, "getPeerCount")) >= PEER_COUNT,
            timeout=180,
        )
        converged = live.wait_value(
            "all peers converge on live mined tip beyond mesh_n_high",
            lambda: all_exact_at_least(hub, peers, TARGET_HEIGHT),
            timeout=900,
            interval=0.5,
        )
        final_height = int(converged["height"])
        canonical_headers = live.wait_value(
            "all canonical hashes match across bounded mesh",
            lambda: all_headers_match(hub, peers, final_height),
            timeout=120,
        )

        # Freeze the producer first so log analysis and persisted peer tips
        # refer to the exact observed boundary.
        hub.stop()
        cleanup_errors.extend(stop_peers(peers))

        peer_logs = {label: log_text(label) for label in peer_labels}
        gossip_receivers = sum(
            "exact direct-child suffix admitted" in text
            or "HeaderDAG-selected exact suffix plan admitted" in text
            for text in peer_logs.values()
        )
        require(
            gossip_receivers == PEER_COUNT,
            f"only {gossip_receivers}/{PEER_COUNT} peers admitted header-first block gossip",
        )
        applied_counts = {
            label: text.count("header-first exact suffix application completed")
            for label, text in peer_logs.items()
        }
        require(
            all(count >= final_height for count in applied_counts.values()),
            f"not every peer applied the full live suffix: {applied_counts}",
        )
        all_logs = {
            bootstrap_label: log_text(bootstrap_label),
            miner_label: log_text(miner_label),
            **peer_logs,
        }
        for label, text in all_logs.items():
            assert_clean(label, text)

        summary.update(
            {
                "status": "passed",
                "converged_tip": converged,
                "canonical_headers": canonical_headers,
                "initial_mesh": initial_mesh,
                "hubless_mesh": hubless_mesh,
                "gossip_receivers": gossip_receivers,
                "min_applied_p2p_blocks": min(applied_counts.values()),
                "max_applied_p2p_blocks": max(applied_counts.values()),
            }
        )
        print(
            f"[PASS] {PEER_COUNT} peers received live blocks through bounded mesh at h{final_height}",
            flush=True,
        )
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        if hub.proc is not None and hub.proc.poll() is None:
            try:
                hub.stop()
            except Exception as caught:
                cleanup_errors.append(f"hub: {caught}")
        cleanup_errors.extend(
            stop_peers(
                [peer for peer in peers if peer.proc is not None and peer.proc.poll() is None]
            )
        )
        if cleanup_errors and error is None:
            error = live.LiveForkReorgError(f"cleanup failures: {cleanup_errors}")
            summary["status"] = "failed"
            summary["error"] = str(error)
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"[summary] {BASE / 'summary.json'}", flush=True)
    if error is not None:
        raise error


if __name__ == "__main__":
    main()
