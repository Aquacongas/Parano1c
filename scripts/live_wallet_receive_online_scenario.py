#!/usr/bin/env python3
"""Online recipient balance updates incrementally after every payment block."""

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
        "NOID_LIVE_WALLET_RECEIVE_ONLINE_DIR",
        str(RUN_PARENT / f"wallet-receive-online-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_WALLET_RECEIVE_ONLINE_BASE_PORT", "22100"))
FUNDING_HEIGHT = 4
PAYMENTS = (110_000, 120_000, 130_000)

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def exact_tip(left, right):
    left_info = left.info()
    right_info = right.info()
    if (
        int(left_info["height"]) == int(right_info["height"])
        and left_info["best_hash"] == right_info["best_hash"]
    ):
        return {
            "height": int(left_info["height"]),
            "hash": left_info["best_hash"],
        }
    return False


def balance(node):
    return rpc(node.rpc_port, "walletGetBalance")


def pending_or_confirmed(node, txid):
    confirmed = rpc(node.rpc_port, "getTx", [txid])
    if confirmed is not None:
        return {"state": "confirmed", "tx": confirmed}
    mempool = rpc(node.rpc_port, "getMempoolInfo")
    if any(entry["tx_hash"] == txid for entry in mempool["txs"]):
        return {"state": "mempool", "txid": txid}
    return False


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
    (RUN_PARENT / "LAST_WALLET_RECEIVE_ONLINE_RUN").write_text(str(BASE) + "\n")

    miner = Node("miner-sender", BASE_PORT, BASE_PORT + 1)
    recipient = Node("online-recipient", BASE_PORT + 10, BASE_PORT + 11)
    nodes = (miner, recipient)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "payments_micronoid": PAYMENTS,
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
        recipient_label = "01-recipient-online-from-h0"
        recipient.start(recipient_label)
        labels.append(recipient_label)
        recipient_address = rpc(recipient.rpc_port, "walletActiveAddress")
        require(
            int(recipient_address["key_index"]) == 0,
            f"unexpected recipient account: {recipient_address}",
        )
        require(
            balance(recipient)["balance_micronoid"] == 0,
            "fresh recipient is not empty",
        )

        miner_label = "02-sender-genesis-miner-three-payments"
        miner.start(miner_label, mode="miner", genesis=True, seeds=[recipient.seed])
        labels.append(miner_label)
        live.wait_value(
            f"online network reaches at least h{FUNDING_HEIGHT}",
            lambda: exact_tip(miner, recipient)
            if miner.height() >= FUNDING_HEIGHT
            else False,
            timeout=900,
        )
        sender_scan = rpc(miner.rpc_port, "walletScan", timeout=180)
        sender_before = balance(miner)
        require(
            int(sender_before["spendable_micronoid"]) > sum(PAYMENTS),
            f"sender lacks funds: {sender_before}",
        )

        expected_balance = 0
        observations = []
        for index, amount in enumerate(PAYMENTS, start=1):
            before = balance(recipient)
            require(
                int(before["balance_micronoid"]) == expected_balance,
                f"recipient balance drift before payment {index}: {before}",
            )
            submitted_at_height = miner.height()
            proof_started = time.monotonic()
            sent = rpc(
                miner.rpc_port,
                "walletSend",
                [recipient_address["address"], amount, 0],
                timeout=300,
            )
            proof_s = time.monotonic() - proof_started
            txid = sent["txid"]
            require(sent["input_count"] >= 1, f"payment {index} has no inputs: {sent}")

            live.wait_value(
                f"payment {index} appears in recipient mempool or chain",
                lambda txid=txid: pending_or_confirmed(recipient, txid),
                timeout=120,
            )
            confirmation_started = time.monotonic()
            confirmed = live.wait_value(
                f"payment {index} confirms on online recipient",
                lambda txid=txid: rpc(recipient.rpc_port, "getTx", [txid]),
                timeout=900,
                interval=0.5,
            )
            expected_balance += amount
            updated = live.wait_value(
                f"recipient balance reflects payment {index} without scan",
                lambda expected=expected_balance, count=index: (
                    current
                    if int(current["balance_micronoid"]) == expected
                    and int(current["utxo_count"]) == count
                    else False
                )
                if (current := balance(recipient))
                else False,
                timeout=120,
            )
            observations.append(
                {
                    "index": index,
                    "amount_micronoid": amount,
                    "submitted_at_height": submitted_at_height,
                    "txid": txid,
                    "send": sent,
                    "proof_and_admission_s": round(proof_s, 3),
                    "confirmed": confirmed,
                    "confirmation_wait_s": round(
                        time.monotonic() - confirmation_started, 3
                    ),
                    "recipient_balance": updated,
                }
            )
            print(
                f"[payment] {index}/{len(PAYMENTS)} h={confirmed['height']} "
                f"balance={updated['balance_micronoid']} utxos={updated['utxo_count']}",
                flush=True,
            )

        final_tip = live.wait_value(
            "sender and online recipient share one final tip",
            lambda: exact_tip(miner, recipient),
            timeout=180,
        )
        final_balance = balance(recipient)
        require(
            int(final_balance["balance_micronoid"]) == sum(PAYMENTS),
            f"final recipient balance is wrong: {final_balance}",
        )
        require(
            int(final_balance["utxo_count"]) == len(PAYMENTS),
            f"final recipient UTXO count is wrong: {final_balance}",
        )
        require(
            int(rpc(recipient.rpc_port, "getMempoolSize")) == 0,
            "recipient mempool is not empty",
        )
        for label in labels:
            assert_clean(label, log_text(label))

        summary.update(
            {
                "status": "passed",
                "recipient_address": recipient_address,
                "sender_scan": sender_scan,
                "sender_before": sender_before,
                "observations": observations,
                "final_tip": final_tip,
                "final_balance": final_balance,
                "recipient_wallet_scan_calls": 0,
            }
        )
        print("[PASS] online recipient updated after every block without walletScan", flush=True)
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
