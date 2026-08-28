#!/usr/bin/env python3
"""Disconnect the selected snapshot source without losing the exact plan.

The scenario reuses the h48/h5 fixtures produced by live_sync_scenarios.py.
Three independent PeerIds serve the same immutable h48 chain and snapshot
generation.  As soon as the empty receiver admits one source's h30 candidate,
that source is killed.  The receiver must retain the plan, fetch its terminal
and State from the remaining peers, then apply the exact h31..h48 suffix.
"""

import datetime
import json
import os
import re
import shutil
import time
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_SNAPSHOT_FAILOVER_DIR",
        str(RUN_PARENT / f"snapshot-source-failover-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_SNAPSHOT_FAILOVER_BASE_PORT", "25300"))

live.BASE = BASE
Node = live.Node
require = live.require


def last_sync_run():
    explicit = os.environ.get("NOID_LIVE_SNAPSHOT_FAILOVER_FIXTURE")
    if explicit:
        return Path(explicit).resolve()
    marker = RUN_PARENT / "LAST_SYNC_RUN"
    require(marker.is_file(), "run live_sync_scenarios.py before snapshot failover")
    return Path(marker.read_text().strip()).resolve()


def clone_chain_fixture(source, destination, include_exports):
    destination.mkdir(parents=True, exist_ok=True)
    for name in (".network-storage-epoch", "mdbx.dat"):
        path = source / name
        require(path.is_file(), f"fixture is missing {path}")
        shutil.copy2(path, destination / name)
    cache = source / "history-step-cache"
    if cache.is_dir():
        shutil.copytree(cache, destination / cache.name)
    if include_exports:
        exports = source / "snapshot-exports"
        require(exports.is_dir(), f"fixture is missing {exports}")
        shutil.copytree(exports, destination / exports.name)


def read_log(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def wait_pattern(label, pattern, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = read_log(label)
        match = pattern.search(text)
        if match is not None:
            return match, text
        time.sleep(0.001)
    raise live.LiveForkReorgError(f"log pattern did not appear: {pattern.pattern}")


def peer_id(label):
    match, _ = wait_pattern(
        label,
        re.compile(r"loaded persistent P2P identity peer=(12D3KooW\S+)"),
        30,
    )
    return match.group(1)


def exact_tip(source, receiver, expected_height):
    left = source.info()
    right = receiver.info()
    if (
        int(left["height"]) == expected_height
        and int(right["height"]) == expected_height
        and left["best_hash"] == right["best_hash"]
    ):
        return {"height": expected_height, "hash": left["best_hash"]}
    return False


def kill_selected_source(node):
    require(node.proc is not None and node.proc.poll() is None, "selected source is not running")
    node.proc.kill()
    node.proc.wait(timeout=10)
    node._close_log()


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    fixture = last_sync_run()
    source_fixture = fixture / "primary" / "data"
    require(source_fixture.is_dir(), f"missing source fixture: {source_fixture}")
    (BASE / "logs").mkdir(parents=True)

    sources = [
        Node(f"source-{index}", BASE_PORT + index * 10, BASE_PORT + index * 10 + 1)
        for index in range(3)
    ]
    receiver = Node("receiver", BASE_PORT + 40, BASE_PORT + 41)
    nodes = [*sources, receiver]
    for node in nodes:
        require(live.port_is_free(node.p2p_port), f"port occupied: {node.p2p_port}")
        require(live.port_is_free(node.rpc_port), f"port occupied: {node.rpc_port}")

    for source in sources:
        clone_chain_fixture(source_fixture, source.data_dir, include_exports=True)

    labels = [f"01-source-{index}" for index in range(3)]
    receiver_label = "02-receiver-h0-failover"
    summary = {
        "run_dir": str(BASE),
        "fixture": str(fixture),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "status": "running",
    }
    error = None
    selected = None
    try:
        for source, label in zip(sources, labels):
            source.start(label)
            require(source.height() == 48, f"{source.name} fixture is not h48")
        identities = {peer_id(label): source for label, source in zip(labels, sources)}
        require(len(identities) == 3, "cloned sources did not create unique P2P identities")

        receiver_started = receiver.spawn(
            receiver_label, seeds=[source.seed for source in sources]
        )
        candidate, _ = wait_pattern(
            receiver_label,
            re.compile(
                r"manifest snapshot boundary ahead .*?from=(12D3KooW[^ ]+) .*?snapshot_height=30"
            ),
            120,
        )
        selected_peer = candidate.group(1)
        require(selected_peer in identities, f"candidate came from unknown peer {selected_peer}")
        selected = identities[selected_peer]
        cut_started = time.monotonic()
        kill_selected_source(selected)
        print(f"[cut] {selected.name} peer={selected_peer} after h30 admission", flush=True)

        receiver.wait_ready(receiver_label, receiver_started, timeout=300)
        surviving = next(source for source in sources if source is not selected)
        converged = live.wait_value(
            "receiver preserves the plan and reaches h48 through alternate sources",
            lambda: exact_tip(surviving, receiver, 48),
            timeout=300,
            interval=0.05,
        )
        elapsed = time.monotonic() - cut_started
        wait_pattern(
            receiver_label,
            re.compile(
                r"header-first exact suffix application completed .*?target_height=48 height=48 blocks=18"
            ),
            30,
        )
        text = read_log(receiver_label)
        terminal_providers = re.findall(
            r"snapshot HistoryStep verification started off-thread .*?terminal_from=(12D3KooW[^ ]+)",
            text,
        )
        segment_providers = re.findall(
            r"received state segment from=(12D3KooW[^ ]+).*?present=true",
            text,
        )
        require(terminal_providers, "no snapshot terminal verification was observed")
        require(segment_providers, "no authenticated State segment was observed")
        require(
            any(peer != selected_peer for peer in terminal_providers),
            "selected source served every terminal before the disconnect",
        )
        require(
            any(peer != selected_peer for peer in segment_providers),
            "selected source served every State segment before the disconnect",
        )
        require(text.count("snapshot install completed") == 1, "snapshot installed more than once")
        require(
            "snapshot_height=30 applied_height=30" in text,
            "receiver did not install the admitted h30 boundary",
        )
        require(
            "target_height=48 height=48 blocks=18" in text,
            "receiver did not apply the exact h31..h48 suffix",
        )
        failures = [
            line
            for line in text.splitlines()
            if any(
                marker in line
                for marker in (
                    " ERROR ",
                    "panicked",
                    "snapshot install failed",
                    "snapshot rejected",
                    "exact suffix transport exhausted",
                )
            )
        ]
        require(not failures, f"receiver contains failures: {failures[-10:]}")

        summary.update(
            {
                "status": "passed",
                "selected_source": selected.name,
                "selected_peer": selected_peer,
                "alternate_terminal_providers": sorted(set(terminal_providers) - {selected_peer}),
                "alternate_segment_providers": sorted(set(segment_providers) - {selected_peer}),
                "elapsed_seconds": round(elapsed, 3),
                "tip": converged,
            }
        )
        print(f"[PASS] snapshot source failover in {elapsed:.3f}s", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        for node in reversed(nodes):
            if node is selected and node.proc is not None and node.proc.poll() is not None:
                continue
            try:
                node.stop()
            except Exception as cleanup_error:
                summary.setdefault("cleanup_errors", []).append(str(cleanup_error))
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"[summary] {BASE / 'summary.json'}", flush=True)
    if error is not None:
        raise error


if __name__ == "__main__":
    main()
