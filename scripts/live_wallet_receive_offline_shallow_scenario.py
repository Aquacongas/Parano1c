#!/usr/bin/env python3
"""Offline recipient recovers a payment through a fresh retained-block gap."""

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
        "NOID_LIVE_WALLET_RECEIVE_OFFLINE_SHALLOW_DIR",
        str(RUN_PARENT / f"wallet-receive-offline-shallow-clean-{STAMP}"),
    )
)
BASE_PORT = int(
    os.environ.get("NOID_LIVE_WALLET_RECEIVE_OFFLINE_SHALLOW_BASE_PORT", "22200")
)
FUNDING_HEIGHT = 4
TRAILING_BLOCKS = 3
PAYMENT_MICRONOID = 250_000
RETAINED_DEPTH = 18

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def exact_tip(left, right, expected_height):
    left_info = left.info()
    right_info = right.info()
    if (
        int(left_info["height"]) == expected_height
        and int(right_info["height"]) == expected_height
        and left_info["best_hash"] == right_info["best_hash"]
    ):
        return {"height": expected_height, "hash": left_info["best_hash"]}
    return False


def balance(node):
    return rpc(node.rpc_port, "walletGetBalance")


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def assert_clean(label, text):
    forbidden = (
        " ERROR ",
        "panicked",
        "P2P network error",
        "P2P block rejected",
        "wallet proof task",
        "wallet builder diverged",
        "mempool relay: lagged",
        "tx rejected",
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
    (RUN_PARENT / "LAST_WALLET_RECEIVE_OFFLINE_SHALLOW_RUN").write_text(
        str(BASE) + "\n"
    )

    sender = Node("sender", BASE_PORT, BASE_PORT + 1)
    recipient = Node("offline-recipient", BASE_PORT + 10, BASE_PORT + 11)
    nodes = (sender, recipient)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "payment_micronoid": PAYMENT_MICRONOID,
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
        wallet_label = "01-recipient-creates-address-at-h0-then-offline"
        recipient.start(wallet_label)
        labels.append(wallet_label)
        recipient_address = rpc(recipient.rpc_port, "walletActiveAddress")
        require(balance(recipient)["balance_micronoid"] == 0, "recipient funded at h0")
        recipient.stop()

        miner_label = "02-sender-mines-and-pays-offline-recipient"
        sender.start(miner_label, mode="miner", genesis=True)
        labels.append(miner_label)
        funded = live.wait_mined(sender, FUNDING_HEIGHT, timeout=900)
        require(
            int(funded["height"]) == FUNDING_HEIGHT,
            f"sender overshot funding height: {funded}",
        )
        sender_scan = rpc(sender.rpc_port, "walletScan", timeout=180)
        sender_before = balance(sender)
        require(
            int(sender_before["spendable_micronoid"]) > PAYMENT_MICRONOID,
            f"sender lacks funds: {sender_before}",
        )

        proof_started = time.monotonic()
        sent = rpc(
            sender.rpc_port,
            "walletSend",
            [recipient_address["address"], PAYMENT_MICRONOID, 0],
            timeout=300,
        )
        proof_s = time.monotonic() - proof_started
        txid = sent["txid"]
        confirmed = live.wait_value(
            "offline recipient payment confirms on sender",
            lambda: rpc(sender.rpc_port, "getTx", [txid]),
            timeout=900,
            interval=0.5,
        )
        confirmation_height = int(confirmed["height"])
        source_tip_height = confirmation_height + TRAILING_BLOCKS
        require(
            source_tip_height <= RETAINED_DEPTH,
            "test setup no longer fits the retained-block window",
        )
        mined_tip = live.wait_mined(sender, source_tip_height, timeout=900)
        require(
            int(mined_tip["height"]) == source_tip_height,
            f"sender overshot shallow source tip: {mined_tip}",
        )
        sender.stop()

        source_label = "03-sender-frozen-shallow-source"
        sender.start(source_label)
        labels.append(source_label)
        require(sender.height() == source_tip_height, "frozen source tip changed")

        recipient_label = "04-recipient-returns-via-direct-sync"
        sync_started = time.monotonic()
        _, startup_s = recipient.start(recipient_label, seeds=[sender.seed])
        labels.append(recipient_label)
        final_tip = live.wait_value(
            "offline recipient directly catches the shallow source",
            lambda: exact_tip(sender, recipient, source_tip_height),
            timeout=600,
        )
        sync_s = time.monotonic() - sync_started
        recipient_balance = balance(recipient)
        require(
            int(recipient_balance["balance_micronoid"]) == PAYMENT_MICRONOID,
            f"shallow-synced recipient balance is wrong: {recipient_balance}",
        )
        require(
            int(recipient_balance["utxo_count"]) == 1,
            f"shallow-synced recipient UTXO count is wrong: {recipient_balance}",
        )
        require(
            rpc(recipient.rpc_port, "getTx", [txid]) == confirmed,
            "recipient transaction index differs from sender",
        )
        owned = rpc(
            recipient.rpc_port, "getSlotsByOwner", [recipient_address["address"]]
        )
        require(
            len(owned) == 1 and int(owned[0]["value"]) == PAYMENT_MICRONOID,
            f"recipient owner index is wrong: {owned}",
        )

        recipient_log = log_text(recipient_label)
        require(
            recipient_log.count("applied P2P block") == source_tip_height,
            "recipient did not apply the complete direct suffix",
        )
        require(
            "snapshot install completed" not in recipient_log,
            "shallow offline recipient unexpectedly used O(1) snapshot",
        )
        require(
            "requesting state manifest" not in recipient_log,
            "shallow offline recipient requested a state manifest",
        )
        for label in labels:
            assert_clean(label, log_text(label))

        summary.update(
            {
                "status": "passed",
                "recipient_address": recipient_address,
                "sender_scan": sender_scan,
                "sender_before": sender_before,
                "send": sent,
                "proof_and_admission_s": round(proof_s, 3),
                "confirmed": confirmed,
                "source_tip": mined_tip,
                "recipient_startup_s": round(startup_s, 3),
                "recipient_sync_s": round(sync_s, 3),
                "final_tip": final_tip,
                "recipient_balance": recipient_balance,
                "owned_slots": owned,
                "recipient_applied_blocks": recipient_log.count("applied P2P block"),
                "recipient_snapshot_installs": recipient_log.count(
                    "snapshot install completed"
                ),
                "recipient_wallet_scan_calls": 0,
            }
        )
        print("[PASS] offline recipient recovered payment through shallow direct sync", flush=True)
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
