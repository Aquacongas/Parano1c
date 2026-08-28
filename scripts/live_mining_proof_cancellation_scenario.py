#!/usr/bin/env python3
"""A canonical peer block must cancel an in-flight local HistoryStep proof."""

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
        "NOID_LIVE_PROOF_CANCEL_DIR",
        str(RUN_PARENT / f"mining-proof-cancel-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_PROOF_CANCEL_BASE_PORT", "23700"))

live.BASE = BASE
Node = live.Node
require = live.require


def status(node):
    return live.rpc(node.rpc_port, "getNodeStatus")


def log_contains(node, needle):
    return node.log_path is not None and needle in node.log_text()


def proof_cancellation_message(node):
    text = node.log_text()
    for message in (
        "canonical/template change cancelled HistoryStep preparation",
        "canonical sync authority cancelled HistoryStep preparation",
    ):
        if message in text:
            return message
    return False


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    ports = tuple(BASE_PORT + offset for offset in (0, 1, 10, 11, 20, 21))
    for port in ports:
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)

    source = Node("source", BASE_PORT, BASE_PORT + 1)
    gate = Node("gate", BASE_PORT + 10, BASE_PORT + 11)
    candidate = Node("candidate", BASE_PORT + 20, BASE_PORT + 21)
    summary: dict[str, object] = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "status": "running",
    }
    error = None

    try:
        source.start("01-source-mine-h1", mode="miner", genesis=True)
        source_h1 = live.wait_mined(source, 1, timeout=900)
        source.stop()

        gate.start("02-gate-h0")
        candidate.start("03-candidate-proof-h1", mode="miner", seeds=[gate.seed])
        ready = live.wait_value(
            "one peer admits candidate mining",
            lambda: status(candidate) if bool(status(candidate)["mining_ready"]) else False,
            timeout=120,
        )
        proof_started_at = time.monotonic()
        live.wait_value(
            "candidate starts its h1 HistoryStep",
            lambda: log_contains(candidate, "mining template ready height=1"),
            timeout=60,
        )
        time.sleep(2)

        source_started_at = time.monotonic()
        source.start("04-source-publishes-h1", seeds=[candidate.seed])
        selected = live.wait_value(
            "candidate adopts source h1 while its own h1 proof is active",
            lambda: candidate.info()
            if int(candidate.info()["height"]) == 1
            and candidate.info()["best_hash"] == source_h1["best_hash"]
            else False,
            timeout=180,
        )
        cancellation_message = live.wait_value(
            "in-flight HistoryStep reports cooperative cancellation",
            lambda: proof_cancellation_message(candidate),
            timeout=60,
        )
        cancellation_seen_at = time.monotonic()

        candidate_h2 = live.wait_mined(candidate, 2, timeout=900)
        candidate_log = candidate.log_text()
        require(
            "block accepted height=1" not in candidate_log,
            "candidate published its stale h1 instead of adopting the peer block",
        )
        require(
            "mining complete block height=1" not in candidate_log,
            "candidate completed the stale h1 proof instead of cancelling it",
        )

        for log_path in sorted((BASE / "logs").glob("*.log")):
            live.assert_clean_log(log_path.stem, log_path.read_text(errors="replace"))

        summary.update(
            {
                "status": "passed",
                "source_h1": source_h1,
                "candidate_gate": ready,
                "selected_peer_h1": selected,
                "candidate_h2": candidate_h2,
                "cancellation_message": cancellation_message,
                "proof_active_before_source_seconds": source_started_at - proof_started_at,
                "source_start_to_adoption_seconds": cancellation_seen_at - source_started_at,
            }
        )
        print("[PASS] canonical peer block cancelled the in-flight local proof", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        for node in (candidate, gate, source):
            try:
                node.stop()
            except Exception as cleanup_error:
                print(f"[cleanup] {node.name}: {cleanup_error}", flush=True)
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"[summary] {BASE / 'summary.json'}", flush=True)

    if error is not None:
        raise error


if __name__ == "__main__":
    main()
