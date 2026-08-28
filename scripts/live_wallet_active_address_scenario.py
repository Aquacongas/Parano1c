#!/usr/bin/env python3
"""Fresh active-address generation, funding, switching, and persistence UX."""

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
        "NOID_LIVE_WALLET_ACTIVE_ADDRESS_DIR",
        str(RUN_PARENT / f"wallet-active-address-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_WALLET_ACTIVE_ADDRESS_BASE_PORT", "22400"))
FUNDING_HEIGHT = 4
PAYMENT_MICRONOID = 450_000

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def balance(node):
    return rpc(node.rpc_port, "walletGetBalance")


def active(node):
    return rpc(node.rpc_port, "walletActiveAddress")


def addresses(node):
    return rpc(node.rpc_port, "walletListAddresses")


def timed_rpc(node, method, params=None, timeout=180):
    started = time.monotonic()
    result = rpc(node.rpc_port, method, params, timeout=timeout)
    return result, time.monotonic() - started


def expected_rpc_error(node, method, params, expected):
    try:
        rpc(node.rpc_port, method, params)
    except live.LiveForkReorgError as error:
        message = str(error)
        require(expected in message, f"unexpected {method} error: {message}")
        return message
    raise live.LiveForkReorgError(f"{method} unexpectedly succeeded")


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


def assert_address_list(node, expected_count, active_index):
    listed = addresses(node)
    require(len(listed) == expected_count, f"address count mismatch: {listed}")
    require(
        [int(item["key_index"]) for item in listed] == list(range(expected_count)),
        f"address indices are not contiguous: {listed}",
    )
    marked = [int(item["key_index"]) for item in listed if item["is_active"]]
    require(marked == [active_index], f"active address markers are wrong: {listed}")
    return listed


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    for port in (BASE_PORT, BASE_PORT + 1):
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_WALLET_ACTIVE_ADDRESS_RUN").write_text(str(BASE) + "\n")

    node = Node("wallet-node", BASE_PORT, BASE_PORT + 1)
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
        setup_label = "01-generate-addresses-at-h0"
        _, setup_startup_s = node.start(setup_label)
        labels.append(setup_label)
        address0 = active(node)
        require(int(address0["key_index"]) == 0, f"unexpected first address: {address0}")
        initial_list = assert_address_list(node, 1, 0)

        address1, generate1_s = timed_rpc(node, "walletNextAddress")
        require(int(address1["key_index"]) == 1, f"next address is wrong: {address1}")
        require(not address1["is_active"], f"new address activated itself: {address1}")
        list_after_generate1 = assert_address_list(node, 2, 0)
        require(active(node) == address0, "address generation changed the active owner")
        require(balance(node)["balance_micronoid"] == 0, "active balance changed at h0")

        invalid_switch_error = expected_rpc_error(
            node,
            "walletSetActiveAddress",
            [2],
            "active address index has not been generated",
        )
        require(active(node) == address0, "failed switch mutated the active account")

        restored0, restore0_s = timed_rpc(node, "walletSetActiveAddress", [0])
        require(restored0["address"] == address0["address"], "failed to restore address 0")
        assert_address_list(node, 2, 0)
        node.stop()

        miner_label = "02-fund-index0-and-pay-inactive-index1"
        node.start(miner_label, mode="miner", genesis=True)
        labels.append(miner_label)
        funded = live.wait_mined(node, FUNDING_HEIGHT, timeout=900)
        require(int(funded["height"]) == FUNDING_HEIGHT, f"funding overshot: {funded}")
        index0_scan = rpc(node.rpc_port, "walletScan", timeout=180)
        index0_before = balance(node)
        require(
            int(index0_before["spendable_micronoid"]) > PAYMENT_MICRONOID,
            f"index 0 lacks funds: {index0_before}",
        )

        sent = rpc(
            node.rpc_port,
            "walletSend",
            [address1["address"], PAYMENT_MICRONOID, 0],
            timeout=300,
        )
        txid = sent["txid"]
        pending_switch_error = expected_rpc_error(
            node,
            "walletSetActiveAddress",
            [1],
            "cannot switch active address while a wallet transaction is pending",
        )
        require(int(active(node)["key_index"]) == 0, "pending switch changed active index")
        confirmed = live.wait_value(
            "payment to inactive local address confirms",
            lambda: rpc(node.rpc_port, "getTx", [txid]),
            timeout=900,
            interval=0.5,
        )
        node.stop()

        switching_label = "03-switch-and-load-confirmed-addresses"
        _, switching_startup_s = node.start(switching_label)
        labels.append(switching_label)
        require(int(active(node)["key_index"]) == 0, "failed pending switch persisted")

        activated1, activate1_s = timed_rpc(node, "walletSetActiveAddress", [1])
        require(activated1["address"] == address1["address"], "index 1 address changed")
        index1_balance = balance(node)
        require(
            int(index1_balance["balance_micronoid"]) == PAYMENT_MICRONOID
            and int(index1_balance["utxo_count"]) == 1,
            f"index 1 balance did not load: {index1_balance}",
        )
        index1_utxos = rpc(node.rpc_port, "walletListUtxos")
        require(
            len(index1_utxos) == 1
            and int(index1_utxos[0]["key_index"]) == 1
            and int(index1_utxos[0]["value_micronoid"]) == PAYMENT_MICRONOID,
            f"index 1 UTXO view is wrong: {index1_utxos}",
        )
        index1_history = rpc(node.rpc_port, "walletHistory")
        # Active-address mode intentionally does not derive or scan every
        # inactive owner on every block. The exact current balance is loaded
        # from the durable owner index when selected; historical incoming rows
        # exist only for periods during which that address was active.
        require(
            not any(item["tx_hash"] == txid for item in index1_history),
            f"inactive incoming payment unexpectedly entered active-only history: {index1_history}",
        )

        address2, generate2_s = timed_rpc(node, "walletNextAddress")
        require(int(address2["key_index"]) == 2, f"third address is wrong: {address2}")
        require(not address2["is_active"], f"third address activated itself: {address2}")
        require(
            balance(node) == index1_balance,
            "inactive address generation changed the active balance",
        )
        list_after_generate2 = assert_address_list(node, 3, 1)

        restored1, restore1_s = timed_rpc(node, "walletSetActiveAddress", [1])
        require(restored1 == activated1, "restored index 1 metadata changed")
        require(balance(node) == index1_balance, "restored index 1 balance changed")
        list_before_restart = assert_address_list(node, 3, 1)
        node.stop()

        persistence_label = "04-active-index1-persists-across-restart"
        _, persistence_startup_s = node.start(persistence_label)
        labels.append(persistence_label)
        persisted_active = active(node)
        persisted_balance = balance(node)
        persisted_list = assert_address_list(node, 3, 1)
        require(persisted_active == activated1, "active index 1 did not persist")
        require(persisted_balance == index1_balance, "index 1 balance did not persist")
        require(
            rpc(node.rpc_port, "walletGetAddress", [0]) == address0["address"]
            and rpc(node.rpc_port, "walletGetAddress", [1]) == address1["address"]
            and rpc(node.rpc_port, "walletGetAddress", [2]) == address2["address"],
            "address derivation changed across restart",
        )

        for label in labels:
            assert_clean(label, log_text(label))
        summary.update(
            {
                "status": "passed",
                "addresses": [address0, address1, address2],
                "initial_list": initial_list,
                "list_after_generate1": list_after_generate1,
                "list_after_generate2": list_after_generate2,
                "list_before_restart": list_before_restart,
                "persisted_list": persisted_list,
                "invalid_switch_error": invalid_switch_error,
                "pending_switch_error": pending_switch_error,
                "index0_scan": index0_scan,
                "index0_before": index0_before,
                "send": sent,
                "confirmed": confirmed,
                "index1_balance": index1_balance,
                "index1_utxos": index1_utxos,
                "index1_history": index1_history,
                "inactive_receive_history_policy": "not recorded; exact balance loads on activation",
                "persisted_active": persisted_active,
                "persisted_balance": persisted_balance,
                "timings_s": {
                    "setup_startup": round(setup_startup_s, 3),
                    "generate_index1": round(generate1_s, 3),
                    "restore_index0": round(restore0_s, 3),
                    "switching_startup": round(switching_startup_s, 3),
                    "activate_funded_index1": round(activate1_s, 3),
                    "generate_index2": round(generate2_s, 3),
                    "restore_index1": round(restore1_s, 3),
                    "persistence_startup": round(persistence_startup_s, 3),
                },
            }
        )
        print("[PASS] active address generation, loading, guards, and persistence", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
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
