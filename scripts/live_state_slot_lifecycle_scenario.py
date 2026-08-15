#!/usr/bin/env python3
"""Fresh-chain durable slot density, clearing, and restart scenario.

This scenario intentionally covers one concern only: physical UTXO state
lifecycle. It uses the production release binary and no saved fixture:

- mine a fresh genesis state into one hot 2^16-slot segment;
- prove salted wallet hints differ locally without selecting other segments;
- cold-restart through compact summaries;
- confirm one ordinary payment and observe its spent input become empty;
- prove coinbase, change, and recipient outputs remain in the same segment;
- cold-restart again and retain the same one-segment durable state.
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
        "NOID_LIVE_STATE_SLOT_DIR",
        str(RUN_PARENT / f"state-slot-lifecycle-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_STATE_SLOT_BASE_PORT", "22700"))
INITIAL_HEIGHT = int(os.environ.get("NOID_LIVE_STATE_SLOT_INITIAL_HEIGHT", "3"))
PAYMENT_MICRONOID = int(os.environ.get("NOID_LIVE_STATE_SLOT_PAYMENT", "1000000"))
SEGMENT_LOG = 16
SEGMENT_RAM_BYTES = 3 * (1 << SEGMENT_LOG) * 16
SPARSE_SEGMENT_HEADER_BYTES = 9
SPARSE_ENTRY_BYTES = 50

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
    "template build failed",
    "coinbase-reuse hydration failed",
)


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def assert_clean(label):
    failures = [
        line
        for line in log_text(label).splitlines()
        if any(marker in line for marker in FAILURE_MARKERS)
    ]
    require(not failures, f"{label} contains failures: {failures[-10:]}")


def compact_metrics(label):
    line = next(
        (
            line
            for line in log_text(label).splitlines()
            if "resumed exact state from compact segment summaries" in line
        ),
        None,
    )
    require(line is not None, f"{label} did not use compact segment summaries")
    assert line is not None
    result = {}
    for field in ("active_segments", "active_slot_count"):
        match = re.search(rf"(?:^|\s){field}=(\d+)(?:\s|$)", line)
        require(match is not None, f"{label} compact log misses {field}: {line}")
        assert match is not None
        result[field] = int(match.group(1))
    return result


def assert_banner_encoded_size(label, expected_bytes):
    state_lines = [
        line
        for line in log_text(label).splitlines()
        if " slots  " in line and " encoded" in line and "domain max" in line
    ]
    require(state_lines, f"{label} has no sparse state banner line")
    require(
        f"{expected_bytes}B encoded" in state_lines[-1],
        f"{label} banner does not report {expected_bytes} encoded bytes: {state_lines[-1]}",
    )


def state_info(node):
    return rpc(node.rpc_port, "getStateInfo")


def assert_one_sparse_segment(node, label):
    info = state_info(node)
    require(int(info["log_slots"]) == 24, f"{label}: unexpected depth: {info}")
    expected_bytes = SPARSE_SEGMENT_HEADER_BYTES + (
        int(info["active_slots"]) * SPARSE_ENTRY_BYTES
    )
    require(
        int(info["state_bytes"]) == expected_bytes,
        f"{label}: expected one canonical sparse segment ({expected_bytes} bytes): {info}",
    )
    print(
        f"[state] {label} active={info['active_slots']} bytes={info['state_bytes']} "
        f"size={info['state_size_human']}",
        flush=True,
    )
    return info


def assert_salted_hints_stay_dense(node, expected_segment, label):
    first = rpc(node.rpc_port, "getSlotHintsSalted", [256, "11" * 32])
    second = rpc(node.rpc_port, "getSlotHintsSalted", [256, "29" * 32])
    require(len(first) == 256 and len(set(first)) == 256, f"{label}: bad first hints")
    require(len(second) == 256 and len(set(second)) == 256, f"{label}: bad second hints")
    require(first != second, f"{label}: salt did not diversify local positions")
    first_segments = {int(slot) >> SEGMENT_LOG for slot in first}
    second_segments = {int(slot) >> SEGMENT_LOG for slot in second}
    require(len(first_segments) == 1, f"{label}: first hints scattered: {first_segments}")
    require(second_segments == first_segments, f"{label}: salt changed segment")
    segment = next(iter(first_segments))
    if expected_segment is not None:
        require(segment == expected_segment, f"{label}: segment {segment} != {expected_segment}")
    print(f"[hints] {label} segment={segment} local_salts_differ=true", flush=True)
    return segment


def wait_tx(node, txid, timeout=900):
    return live.wait_value(
        f"transaction {txid[:12]} confirmed",
        lambda: rpc(node.rpc_port, "getTx", [txid]),
        timeout=timeout,
        interval=0.25,
    )


def stop_if_running(node, cleanup):
    if node.proc is None or node.proc.poll() is not None:
        return
    try:
        node.stop()
    except Exception as error:
        cleanup.append(str(error))


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    for port in (BASE_PORT, BASE_PORT + 1):
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_STATE_SLOT_RUN").write_text(str(BASE) + "\n")

    node = Node("state-miner", BASE_PORT, BASE_PORT + 1)
    labels = []
    cleanup = []
    error = None
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "initial_height_target": INITIAL_HEIGHT,
        "payment_micronoid": PAYMENT_MICRONOID,
        "dense_segment_ram_bytes": SEGMENT_RAM_BYTES,
        "sparse_segment_header_bytes": SPARSE_SEGMENT_HEADER_BYTES,
        "sparse_entry_bytes": SPARSE_ENTRY_BYTES,
        "status": "running",
    }
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={summary['binary_sha256']} size={summary['binary_size']}",
        flush=True,
    )

    try:
        # Create the receiving key at h0, then restore payout account 0 before
        # genesis mining so every reward and later change has one known owner.
        setup_label = "01-wallet-setup-h0"
        node.start(setup_label)
        labels.append(setup_label)
        sender = rpc(node.rpc_port, "walletActiveAddress")
        recipient = rpc(node.rpc_port, "walletNextAddress")
        require(int(sender["key_index"]) == 0, f"unexpected sender: {sender}")
        require(int(recipient["key_index"]) == 1, f"unexpected recipient: {recipient}")
        rpc(node.rpc_port, "walletSetActiveAddress", [0])
        node.stop()

        mining_label = "02-fresh-genesis-density"
        node.start(mining_label, mode="miner", genesis=True)
        labels.append(mining_label)
        live.wait_mined(node, INITIAL_HEIGHT, timeout=900)
        rpc(node.rpc_port, "walletScan", timeout=180)
        initial_state = assert_one_sparse_segment(node, "fresh mining")
        initial_segment = assert_salted_hints_stay_dense(node, None, "fresh mining")
        node.stop()

        restart_label = "03-compact-restart-payment"
        restart_info, restart_seconds = node.start(
            restart_label,
            mode="miner",
            genesis=True,
        )
        labels.append(restart_label)
        restart_metrics = compact_metrics(restart_label)
        require(restart_metrics["active_segments"] == 1, f"bad restart metrics: {restart_metrics}")
        require(int(restart_info["height"]) >= INITIAL_HEIGHT, f"restart lost state: {restart_info}")
        assert_banner_encoded_size(restart_label, int(initial_state["state_bytes"]))
        rpc(node.rpc_port, "walletScan", timeout=180)

        before_utxos = rpc(node.rpc_port, "walletListUtxos")
        require(before_utxos, "sender has no UTXOs after scan")
        plan = rpc(
            node.rpc_port,
            "walletPlanSend",
            [recipient["address"], PAYMENT_MICRONOID, 0],
        )
        require(int(plan["input_count"]) == 1, f"scenario requires one input: {plan}")
        before_slots = {int(utxo["slot_index"]) for utxo in before_utxos}
        sent = rpc(
            node.rpc_port,
            "walletSend",
            [recipient["address"], PAYMENT_MICRONOID, 0],
            timeout=300,
        )
        txid = sent.get("txid") or sent.get("tx_hash")
        require(txid, f"walletSend omitted txid: {sent}")
        confirmed = wait_tx(node, txid)

        after_utxos = rpc(node.rpc_port, "walletListUtxos")
        after_slots = {int(utxo["slot_index"]) for utxo in after_utxos}
        spent_slots = before_slots - after_slots
        require(len(spent_slots) == 1, f"expected one cleared input: {spent_slots}")
        spent_slot = next(iter(spent_slots))
        spent_state = rpc(node.rpc_port, "getSlot", [spent_slot])
        require(spent_state["empty"], f"spent input did not clear: {spent_state}")

        recipient_slots = rpc(node.rpc_port, "getSlotsByOwner", [recipient["address"]])
        require(len(recipient_slots) == 1, f"recipient output missing: {recipient_slots}")
        require(
            int(recipient_slots[0]["value"]) == PAYMENT_MICRONOID,
            f"recipient amount changed: {recipient_slots}",
        )
        require(
            int(recipient_slots[0]["slot_index"]) >> SEGMENT_LOG == initial_segment,
            f"recipient output escaped dense segment: {recipient_slots}",
        )
        require(
            all(int(utxo["slot_index"]) >> SEGMENT_LOG == initial_segment for utxo in after_utxos),
            "sender change/rewards escaped dense segment",
        )
        post_payment_state = assert_one_sparse_segment(node, "post payment")
        assert_salted_hints_stay_dense(node, initial_segment, "post payment")
        node.stop()

        final_label = "04-final-compact-verification"
        final_info, final_seconds = node.start(final_label)
        labels.append(final_label)
        final_metrics = compact_metrics(final_label)
        require(final_metrics["active_segments"] == 1, f"bad final metrics: {final_metrics}")
        assert_banner_encoded_size(final_label, int(post_payment_state["state_bytes"]))
        require(
            int(final_info["height"]) >= int(confirmed["height"]),
            f"final restart lost payment: {final_info}",
        )
        require(rpc(node.rpc_port, "getTx", [txid]) == confirmed, "tx index changed")
        final_state = assert_one_sparse_segment(node, "final restart")
        assert_salted_hints_stay_dense(node, initial_segment, "final restart")
        node.stop()

        for label in labels:
            assert_clean(label)

        summary.update(
            {
                "status": "passed",
                "sender": sender,
                "recipient": recipient,
                "initial_segment": initial_segment,
                "initial_state": initial_state,
                "restart_seconds": restart_seconds,
                "restart_metrics": restart_metrics,
                "transaction": sent,
                "confirmation": confirmed,
                "cleared_input_slot": spent_slot,
                "recipient_slot": recipient_slots[0],
                "post_payment_state": post_payment_state,
                "final_restart_seconds": final_seconds,
                "final_restart_metrics": final_metrics,
                "final_state": final_state,
                "logs": labels,
            }
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
    print("STATE SLOT LIFECYCLE LIVE SCENARIO PASSED", flush=True)


if __name__ == "__main__":
    main()
