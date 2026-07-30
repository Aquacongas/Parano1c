#!/usr/bin/env python3
"""Fresh-chain incremental state-snapshot publication and O(1) sync.

This is intentionally one isolated scenario. A release miner creates a new
chain while snapshot generations advance in the background. The test waits
for a full generation followed by a delta generation that is still inside the
18-block serving suffix, freezes the source, and joins one empty release node.
"""

import datetime
import json
import os
import re
import time
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_INCREMENTAL_SNAPSHOT_DIR",
        str(RUN_PARENT / f"incremental-snapshot-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_INCREMENTAL_SNAPSHOT_BASE_PORT", "22900"))
RETAINED_DEPTH = 18
MIN_SOURCE_HEIGHT = 21

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def read_log(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def field(line, name):
    match = re.search(rf"(?:^|\s){re.escape(name)}=([^\s]+)(?:\s|$)", line)
    return match.group(1) if match else None


def snapshot_builds(text):
    builds = []
    for line in text.splitlines():
        if "assembled bounded disk snapshot generation" not in line:
            continue
        base = field(line, "incremental_base_height")
        builds.append(
            {
                "target_height": int(field(line, "target_height")),
                "incremental_base_height": None
                if base == "None"
                else int(re.fullmatch(r"Some\((\d+)\)", base).group(1)),
                "reused_segments": int(field(line, "reused_segments")),
                "rebuilt_segments": int(field(line, "rebuilt_segments")),
                "output_segments": int(field(line, "output_segments")),
            }
        )
    return builds


def serveable_delta(miner, label):
    info = miner.info()
    height = int(info["height"])
    builds = snapshot_builds(read_log(label))
    if height < MIN_SOURCE_HEIGHT or len(builds) < 2:
        return False
    latest = builds[-1]
    if latest["incremental_base_height"] is None:
        return False
    if height - latest["target_height"] > RETAINED_DEPTH:
        return False
    return {"tip": info, "builds": builds}


def exact_tip(left, right, expected_height):
    a = left.info()
    b = right.info()
    if (
        int(a["height"]) == expected_height
        and int(b["height"]) == expected_height
        and a["best_hash"] == b["best_hash"]
    ):
        return {"height": expected_height, "hash": a["best_hash"]}
    return False


FAILURE_MARKERS = (
    " ERROR ",
    "panicked",
    "snapshot generation build failed",
    "snapshot rejected",
    "snapshot install failed",
    "P2P network error",
    "P2P block rejected",
    "block sync request failed",
    "unknown or delayed retained-block response",
    "HistoryStep terminal request failed",
    "HistoryStep terminal response failed",
)


def assert_clean(label, text):
    failures = [
        line for line in text.splitlines() if any(token in line for token in FAILURE_MARKERS)
    ]
    require(not failures, f"{label} contains failures: {failures[-10:]}")


def stop_if_running(node, cleanup):
    if node.proc is None or node.proc.poll() is not None:
        return
    try:
        node.stop()
    except Exception as error:
        cleanup.append(f"{node.name}: {error}")


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    for port in (BASE_PORT, BASE_PORT + 1, BASE_PORT + 10, BASE_PORT + 11):
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_INCREMENTAL_SNAPSHOT_RUN").write_text(str(BASE) + "\n")

    source = Node("source", BASE_PORT, BASE_PORT + 1)
    receiver = Node("receiver", BASE_PORT + 10, BASE_PORT + 11)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "retained_depth": RETAINED_DEPTH,
        "status": "running",
    }
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={summary['binary_sha256']} size={summary['binary_size']}",
        flush=True,
    )

    labels = []
    cleanup = []
    error = None
    try:
        mining_label = "01-source-fresh-mining-and-delta-publication"
        source.start(mining_label, mode="miner", genesis=True)
        labels.append(mining_label)
        live.wait_mined(source, MIN_SOURCE_HEIGHT, timeout=1800)
        ready = live.wait_value(
            "full then serveable incremental snapshot while mining",
            lambda: serveable_delta(source, mining_label),
            timeout=900,
            interval=0.5,
        )
        source.request_stop()
        source.finish_stop()

        source_tip = ready["tip"]
        source_height = int(source_tip["height"])
        builds = snapshot_builds(read_log(mining_label))
        require(builds[0]["incremental_base_height"] is None, "first snapshot was not full")
        require(
            any(item["incremental_base_height"] is not None for item in builds[1:]),
            f"no incremental generation was published: {builds}",
        )
        latest = builds[-1]
        require(
            source_height - latest["target_height"] <= RETAINED_DEPTH,
            f"latest snapshot is outside retained suffix: tip={source_height}, builds={builds}",
        )

        export_dirs = sorted(
            path.name
            for path in (source.data_dir / "snapshot-exports").iterdir()
            if path.is_dir() and re.fullmatch(r"snapshot-v\d+-[0-9a-f-]+", path.name)
        )
        require(
            len(export_dirs) >= 2,
            f"fewer than two immutable snapshot generations persisted: {export_dirs}",
        )

        source_label = "02-source-frozen-restart"
        source.start(source_label)
        labels.append(source_label)
        require(source.height() == source_height, "source tip changed across passive restart")

        receiver_label = "03-empty-receiver-o1-sync"
        sync_started = time.monotonic()
        _, receiver_startup_s = receiver.start(receiver_label, seeds=[source.seed])
        labels.append(receiver_label)
        converged = live.wait_value(
            "empty receiver installs state and exact retained suffix",
            lambda: exact_tip(source, receiver, source_height),
            timeout=1200,
            interval=0.5,
        )
        sync_s = time.monotonic() - sync_started
        headers = live.wait_value(
            "all canonical headers match after snapshot sync",
            lambda: live.exact_headers(source, receiver, source_height),
            timeout=180,
        )

        receiver_log = read_log(receiver_label)
        boundaries = [
            int(value)
            for value in re.findall(
                r"snapshot boundary and disk tail fully applied snapshot_height=(\d+)",
                receiver_log,
            )
        ]
        require(len(boundaries) == 1, f"receiver snapshot boundary count is wrong: {boundaries}")
        require(
            source_height - boundaries[0] == RETAINED_DEPTH,
            f"receiver did not apply the exact 18-block suffix: tip={source_height}, boundary={boundaries}",
        )
        require(
            receiver_log.count("snapshot install completed") == 1,
            "receiver did not install exactly one snapshot",
        )
        suffix_counts = [
            int(value)
            for value in re.findall(
                r'phase="retained_suffix_apply"[^\n]* count=(\d+)',
                receiver_log,
            )
        ]
        require(suffix_counts == [RETAINED_DEPTH], f"disk-tail telemetry is wrong: {suffix_counts}")

        for label in labels:
            assert_clean(label, read_log(label))

        summary.update(
            {
                "status": "passed",
                "source_tip": source_tip,
                "snapshot_builds": builds,
                "persisted_generations": export_dirs,
                "receiver_startup_s": round(receiver_startup_s, 3),
                "receiver_sync_s": round(sync_s, 3),
                "receiver_snapshot_boundary": boundaries[0],
                "receiver_staged_suffix_blocks": suffix_counts[0],
                "converged_tip": converged,
                "matched_header_count": len(headers),
                "source_state": rpc(source.rpc_port, "getStateInfo"),
                "receiver_state": rpc(receiver.rpc_port, "getStateInfo"),
            }
        )
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = repr(caught)
    finally:
        stop_if_running(receiver, cleanup)
        stop_if_running(source, cleanup)
        if cleanup:
            summary["cleanup_errors"] = cleanup
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2), flush=True)

    if error is not None:
        raise error


if __name__ == "__main__":
    main()
