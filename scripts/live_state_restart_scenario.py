#!/usr/bin/env python3
"""Fresh-chain compact-state restart and cold-first-block live scenario.

The production release binary creates the chain from genesis, mines its own
state, stops cleanly, resumes that exact state through compact segment
summaries, and mines the first post-restart block. No saved chain fixture or
debug-only path is used.
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
        "NOID_LIVE_STATE_RESTART_DIR",
        str(RUN_PARENT / f"state-restart-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_STATE_RESTART_BASE_PORT", "22500"))
INITIAL_HEIGHT = int(os.environ.get("NOID_LIVE_STATE_RESTART_INITIAL_HEIGHT", "3"))

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


FAILURE_MARKERS = (
    " ERROR ",
    "panicked",
    "P2P network error",
    "P2P block rejected",
    "wallet proof task",
    "wallet builder diverged",
)


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def assert_clean(label, text):
    failures = [
        line
        for line in text.splitlines()
        if any(marker in line for marker in FAILURE_MARKERS)
    ]
    require(not failures, f"{label} contains failures: {failures[-10:]}")


def compact_resume_metrics(text):
    line = next(
        (
            line
            for line in text.splitlines()
            if "resumed exact state from compact segment summaries" in line
        ),
        None,
    )
    require(line is not None, "restart did not use compact segment summaries")
    metrics = {}
    for field in ("active_segments", "active_slot_count"):
        match = re.search(rf"(?:^|\s){field}=(\d+)(?:\s|$)", line)
        require(match is not None, f"compact resume log misses {field}: {line}")
        metrics[field] = int(match.group(1))
    return metrics


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
    for port in (BASE_PORT, BASE_PORT + 1):
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_STATE_RESTART_RUN").write_text(str(BASE) + "\n")

    node = Node("fresh-miner", BASE_PORT, BASE_PORT + 1)
    labels = []
    cleanup = []
    error = None
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "initial_height_target": INITIAL_HEIGHT,
        "status": "running",
    }
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={summary['binary_sha256']} size={summary['binary_size']}",
        flush=True,
    )

    try:
        initial_label = "01-fresh-genesis-mining"
        node.start(initial_label, mode="miner", genesis=True)
        labels.append(initial_label)
        live.wait_mined(node, INITIAL_HEIGHT, timeout=900)
        node.stop()

        resume_label = "02-compact-node-restart"
        resume_info, resume_seconds = node.start(resume_label)
        labels.append(resume_label)
        resume_height = int(resume_info["height"])
        require(
            resume_height >= INITIAL_HEIGHT,
            f"restart lost mined state: {resume_info}",
        )
        resume_metrics = compact_resume_metrics(log_text(resume_label))
        balance_after_resume = rpc(node.rpc_port, "walletGetBalance")
        node.stop()

        cold_miner_label = "03-cold-post-restart-mining"
        _, cold_startup_seconds = node.start(cold_miner_label, mode="miner")
        labels.append(cold_miner_label)
        cold_parent_height = node.height()
        cold_started = time.monotonic()
        cold_tip = live.wait_mined(node, cold_parent_height + 1, timeout=900)
        cold_first_block_seconds = time.monotonic() - cold_started
        node.stop()

        final_label = "04-final-compact-restart"
        final_info, final_startup_seconds = node.start(final_label)
        labels.append(final_label)
        require(
            int(final_info["height"]) >= cold_parent_height + 1,
            f"final restart lost cold-mined block: {final_info}",
        )
        final_metrics = compact_resume_metrics(log_text(final_label))
        final_balance = rpc(node.rpc_port, "walletGetBalance")
        node.stop()

        for label in labels:
            assert_clean(label, log_text(label))

        summary.update(
            {
                "status": "passed",
                "initial_mined_height": resume_height,
                "compact_restart_seconds": resume_seconds,
                "compact_restart_metrics": resume_metrics,
                "balance_after_resume": balance_after_resume,
                "cold_miner_startup_seconds": cold_startup_seconds,
                "cold_first_block_seconds": cold_first_block_seconds,
                "cold_tip_height": int(cold_tip["height"]),
                "final_restart_seconds": final_startup_seconds,
                "final_restart_metrics": final_metrics,
                "final_balance": final_balance,
                "logs": labels,
            }
        )
        print(
            "[result] "
            f"resume={resume_seconds:.3f}s "
            f"cold_startup={cold_startup_seconds:.3f}s "
            f"first_block={cold_first_block_seconds:.3f}s "
            f"final_resume={final_startup_seconds:.3f}s",
            flush=True,
        )
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
    finally:
        stop_if_running(node, cleanup)
        if cleanup:
            summary["cleanup_errors"] = cleanup
        summary_path = BASE / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(f"[summary] {summary_path}", flush=True)

    if error is not None:
        raise error
    require(not cleanup, f"cleanup failed: {cleanup}")


if __name__ == "__main__":
    main()
