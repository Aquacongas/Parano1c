#!/usr/bin/env python3
"""Live exact-object propagation through a bounded non-hub peer mesh.

Followers form an explicit ring before the producer joins through one bounded
neighbour path. Every block must propagate through that mesh and converge on
all followers without requiring the producer to accept a direct connection
from every node. The topology uses only loopback addresses. Run it in an
isolated network namespace because the production node intentionally keeps
mDNS enabled and a public GUI on the host must not leak mainnet into
this fresh chain.
"""

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
        "NOID_LIVE_EXACT_FANOUT_DIR",
        str(RUN_PARENT / f"exact-object-fanout-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_EXACT_FANOUT_BASE_PORT", "24600"))
PEER_COUNT = int(os.environ.get("NOID_LIVE_EXACT_FANOUT_PEERS", "24"))
TARGET_HEIGHT = int(os.environ.get("NOID_LIVE_EXACT_FANOUT_HEIGHT", "3"))

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def peer_mesh_ready(peers, minimum_connections):
    counts = [int(rpc(peer.rpc_port, "getPeerCount")) for peer in peers]
    if all(count >= minimum_connections for count in counts):
        return {"minimum": min(counts), "maximum": max(counts)}
    return False


def canonical_header(node, height):
    header = rpc(node.rpc_port, "getBlockHeader", [height])
    return header if header is not None else False


def all_peers_have_header(peers, height, expected_hash):
    for peer in peers:
        header = rpc(peer.rpc_port, "getBlockHeader", [height])
        if header is None or header["hash"] != expected_hash:
            return False
    return True


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def assert_clean(label, text):
    forbidden = (
        " ERROR ",
        "panicked",
        "P2P network error",
        "reorg failed",
        "P2P block rejected",
        "exact suffix transport became extinct",
    )
    failures = [line for line in text.splitlines() if any(item in line for item in forbidden)]
    require(not failures, f"{label} contains failures: {failures[-10:]}")


def stop_all(nodes):
    errors = []
    for node in reversed(nodes):
        try:
            node.request_stop()
        except Exception as error:
            errors.append(f"request {node.name}: {error}")
    for node in reversed(nodes):
        try:
            node.finish_stop()
        except Exception as error:
            errors.append(f"finish {node.name}: {error}")
    return errors


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(8 <= PEER_COUNT <= 64, "fanout must exercise a non-trivial local mesh")
    require(TARGET_HEIGHT >= 1, "target height must be positive")
    require(not BASE.exists(), f"run directory already exists: {BASE}")

    producer = Node("producer", BASE_PORT, BASE_PORT + 1)
    peers = [
        Node(f"peer-{index:02d}", BASE_PORT + 100 + index * 2, BASE_PORT + 101 + index * 2)
        for index in range(PEER_COUNT)
    ]
    nodes = [producer, *peers]
    for node in nodes:
        require(live.port_is_free(node.p2p_port), f"port occupied: {node.p2p_port}")
        require(live.port_is_free(node.rpc_port), f"port occupied: {node.rpc_port}")

    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_EXACT_OBJECT_FANOUT_RUN").write_text(str(BASE) + "\n")
    binary_hash = live.sha256(live.NODE_BIN)
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={binary_hash} size={live.NODE_BIN.stat().st_size} peers={PEER_COUNT}",
        flush=True,
    )

    bootstrap_label = "01-producer-bootstrap"
    peer_labels = [f"02-peer-{index:02d}" for index in range(PEER_COUNT)]
    miner_label = "03-producer-miner"
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": binary_hash,
        "peer_count": PEER_COUNT,
        "target_height": TARGET_HEIGHT,
        "status": "running",
    }
    error = None
    cleanup_errors = []
    # Loopback addresses are deliberately excluded from public Kademlia
    # discovery. Two explicit neighbours therefore define a deterministic
    # local ring; public/NAT discovery and relay expansion are covered by the
    # separate relay-mesh scenario.
    mesh_minimum = 2

    try:
        producer.start(bootstrap_label, genesis=True)
        starts = []
        for index, (peer, label) in enumerate(zip(peers, peer_labels)):
            neighbour_seeds = {
                peers[(index - 1) % PEER_COUNT].seed,
                peers[(index + 1) % PEER_COUNT].seed,
            }
            starts.append(peer.spawn(label, seeds=sorted(neighbour_seeds)))
        for peer, label, started in zip(peers, peer_labels, starts):
            peer.wait_ready(label, started, timeout=300)

        initial_mesh = live.wait_value(
            "explicit non-hub ring is connected",
            lambda: peer_mesh_ready(peers, mesh_minimum),
            timeout=180,
            interval=0.25,
        )

        producer.stop()
        hubless_mesh = live.wait_value(
            "followers remain connected without the producer",
            lambda: peer_mesh_ready(peers, mesh_minimum),
            timeout=120,
            interval=0.25,
        )
        producer.start(miner_label, mode="miner", seeds=[peers[0].seed])
        producer_mesh = live.wait_value(
            "producer joins the follower mesh through a bounded path",
            lambda: int(rpc(producer.rpc_port, "getPeerCount")) >= 1,
            timeout=180,
            interval=0.25,
        )

        propagation = []
        for height in range(1, TARGET_HEIGHT + 1):
            header = live.wait_value(
                f"producer commits h{height}",
                lambda height=height: canonical_header(producer, height),
                timeout=900,
                interval=0.1,
            )
            observed_at = time.monotonic()
            expected_hash = header["hash"]
            live.wait_value(
                f"all followers commit canonical h{height}",
                lambda height=height, expected_hash=expected_hash: all_peers_have_header(
                    peers, height, expected_hash
                ),
                timeout=120,
                interval=0.1,
            )
            elapsed = time.monotonic() - observed_at
            propagation.append({"height": height, "seconds": round(elapsed, 3)})
            print(f"[fanout] h{height} all={elapsed:.3f}s", flush=True)

        producer.stop()
        final_target = live.wait_value(
            "followers retain the requested target after producer shutdown",
            lambda: all_peers_have_header(peers, TARGET_HEIGHT, expected_hash),
            timeout=30,
            interval=0.25,
        )
        final_heights = [peer.height() for peer in peers]
        cleanup_errors.extend(stop_all(peers))

        miner_log = log_text(miner_label)
        peer_logs = {label: log_text(label) for label in peer_labels}
        all_logs = {bootstrap_label: log_text(bootstrap_label), miner_label: miner_log, **peer_logs}
        for label, text in all_logs.items():
            assert_clean(label, text)

        applications = {
            label: text.count("header-first exact suffix application completed")
            for label, text in peer_logs.items()
        }
        # The RPC checks above prove that every requested height was committed.
        # A follower may receive hN and hN+1 together and legitimately log one
        # exact-suffix application whose target is higher than N.
        server_busy = miner_log.count("exact-object serving queue is full")
        client_busy = sum(
            text.count("exact-object provider is busy; plan and source retained")
            for text in peer_logs.values()
        )
        header_server_busy = sum(
            text.count("header preparation workers are full") for text in all_logs.values()
        )
        header_client_busy = sum(
            text.count("header source is temporarily busy") for text in all_logs.values()
        )
        summary.update(
            {
                "status": "passed",
                "initial_mesh": initial_mesh,
                "hubless_mesh": hubless_mesh,
                "producer_mesh": producer_mesh,
                "propagation": propagation,
                "max_propagation_s": max(item["seconds"] for item in propagation),
                "server_busy_responses": server_busy,
                "client_busy_responses": client_busy,
                "header_server_busy_responses": header_server_busy,
                "header_client_busy_responses": header_client_busy,
                "final_target": {
                    "height": TARGET_HEIGHT,
                    "hash": expected_hash,
                    "retained": final_target,
                },
                # The continuously running miner can publish a later block
                # while the target is fanning out. That opportunistic suffix
                # is outside this scenario's assertion and may be at different
                # verification stages when the producer stops.
                "final_observed_height_min": min(final_heights),
                "final_observed_height_max": max(final_heights),
                "min_exact_applications": min(applications.values()),
            }
        )
        print(
            f"[PASS] exact-object fanout max={summary['max_propagation_s']:.3f}s "
            f"object_busy={server_busy}/{client_busy} "
            f"header_busy={header_server_busy}/{header_client_busy}",
            flush=True,
        )
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        running = [node for node in nodes if node.proc is not None and node.proc.poll() is None]
        cleanup_errors.extend(stop_all(running))
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
