#!/usr/bin/env python3
"""Fresh direct catch-up plus live gossip without probing past the announced tip."""

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
        "NOID_LIVE_SYNC_ANNOUNCED_TIP_DIR",
        str(RUN_PARENT / f"sync-announced-tip-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_SYNC_ANNOUNCED_TIP_BASE_PORT", "22000"))
DIRECT_TIP = 2
GOSSIP_TIP = 3

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def exact_tip(left, right, height):
    left_info = left.info()
    right_info = right.info()
    if (
        int(left_info["height"]) == height
        and int(right_info["height"]) == height
        and left_info["best_hash"] == right_info["best_hash"]
    ):
        return {"height": height, "hash": left_info["best_hash"]}
    return False


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def assert_clean(label, text):
    forbidden = (
        " ERROR ",
        "panicked",
        "P2P network error",
        "P2P block rejected",
        "block sync request failed",
        "unknown or delayed retained-block response",
    )
    failures = [
        line for line in text.splitlines() if any(token in line for token in forbidden)
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
    (RUN_PARENT / "LAST_SYNC_ANNOUNCED_TIP_RUN").write_text(str(BASE) + "\n")

    source = Node("source", BASE_PORT, BASE_PORT + 1)
    sink = Node("sink", BASE_PORT + 10, BASE_PORT + 11)
    nodes = (source, sink)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "status": "running",
    }
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={summary['binary_sha256']} size={summary['binary_size']}",
        flush=True,
    )

    error = None
    cleanup = []
    labels = []
    try:
        bootstrap_label = "01-source-fresh-genesis-to-h2"
        source.start(bootstrap_label, mode="miner", genesis=True)
        labels.append(bootstrap_label)
        mined = live.wait_mined(source, DIRECT_TIP, timeout=600)
        require(int(mined["height"]) == DIRECT_TIP, "source overshot fresh h2 target")
        source.stop()

        source_label = "02-source-h2-node"
        source.start(source_label)
        labels.append(source_label)
        require(source.height() == DIRECT_TIP, "source overshot direct-sync parent")

        sink_label = "03-sink-fresh-direct-then-gossip"
        sink.start(sink_label, seeds=[source.seed])
        labels.append(sink_label)
        direct_started = time.monotonic()
        direct_tip = live.wait_value(
            "fresh sink directly catches announced h2",
            lambda: exact_tip(source, sink, DIRECT_TIP),
            timeout=300,
        )
        direct_s = time.monotonic() - direct_started

        sink_after_direct = log_text(sink_label)
        require(
            sink_after_direct.count("header-first exact suffix application completed") == 1
            and "target_height=2 height=2 blocks=2" in sink_after_direct,
            "direct catch-up did not atomically apply exact h1..h2",
        )
        require(
            "requesting state segment" not in sink_after_direct
            and "snapshot install completed" not in sink_after_direct,
            "caught-up direct suffix entered the State snapshot path",
        )
        require(
            "requested recent block unavailable" not in sink_after_direct,
            "caught-up direct suffix probed h3",
        )

        source.stop()
        live_miner_label = "04-source-live-h3-miner"
        source.start(
            live_miner_label,
            mode="miner",
            genesis=True,
            seeds=[sink.seed],
        )
        labels.append(live_miner_label)
        gossip_started = time.monotonic()
        mined = live.wait_mined(source, GOSSIP_TIP, timeout=600)
        require(int(mined["height"]) == GOSSIP_TIP, "source overshot live h3 target")
        gossip_tip = live.wait_value(
            "sink applies live h3 gossip on the same tip",
            lambda: exact_tip(source, sink, GOSSIP_TIP),
            timeout=300,
        )
        gossip_s = time.monotonic() - gossip_started
        source.stop()

        sink_final = log_text(sink_label)
        require(
            sink_final.count("header-first exact suffix application completed") == 2,
            "sink did not complete the h1..h2 and h3 exact suffix plans",
        )
        require(
            "exact direct-child suffix admitted" in sink_final
            and "target_height=3 height=3 blocks=1" in sink_final,
            "h3 did not exercise header-first direct-child gossip",
        )
        require(
            "requesting state segment" not in sink_final
            and "snapshot install completed" not in sink_final,
            "live caught-up gossip entered the State snapshot path",
        )
        require(
            "requested recent block unavailable" not in sink_final,
            "live caught-up gossip probed h4",
        )
        for label in labels:
            assert_clean(label, log_text(label))

        summary.update(
            {
                "status": "passed",
                "direct_tip": direct_tip,
                "direct_sync_s": round(direct_s, 3),
                "gossip_tip": gossip_tip,
                "live_gossip_s": round(gossip_s, 3),
                "sink_applied_blocks": sink_final.count("applied P2P block"),
                "sink_manifest_requests": sink_final.count("requesting state manifest"),
                "sink_unavailable_responses": sink_final.count(
                    "requested recent block unavailable"
                ),
            }
        )
        print("[PASS] direct and live sync stop exactly at the announced tip", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        for node in reversed(nodes):
            stop_if_running(node, cleanup)
        if cleanup and error is None:
            error = live.LiveForkReorgError(f"cleanup failures: {cleanup}")
            summary["status"] = "failed"
            summary["error"] = str(error)
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"[summary] {BASE / 'summary.json'}", flush=True)
    if error is not None:
        raise error


if __name__ == "__main__":
    main()
