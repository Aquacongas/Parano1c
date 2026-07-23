#!/usr/bin/env python3
"""Live inactive-address creation and atomic mining-payout switching."""

import datetime
import json
import os
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_WALLET_PAYOUT_SWITCH_DIR",
        str(RUN_PARENT / f"wallet-payout-switch-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_WALLET_PAYOUT_SWITCH_BASE_PORT", "23900"))

live.BASE = BASE
Node = live.Node
rpc = live.rpc
require = live.require


def active(node):
    return rpc(node.rpc_port, "walletActiveAddress")


def addresses(node):
    return rpc(node.rpc_port, "walletListAddresses")


def mined_block(node, height):
    page = rpc(node.rpc_port, "walletMinedBlocks", [1, 50])
    return next(
        (block for block in page["blocks"] if int(block["height"]) == int(height)),
        False,
    )


def wait_payout(node, height, key_index, timeout=900):
    return live.wait_value(
        f"block {height} pays address {key_index}",
        lambda: (
            block
            if (block := mined_block(node, height))
            and int(block["payout_key_index"]) == key_index
            else False
        ),
        timeout=timeout,
        interval=0.25,
    )


def stop_if_running(node):
    if node.proc is not None and node.proc.poll() is None:
        node.stop()


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    for port in (BASE_PORT, BASE_PORT + 1):
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_WALLET_PAYOUT_SWITCH_RUN").write_text(str(BASE) + "\n")

    node = Node("wallet-miner", BASE_PORT, BASE_PORT + 1)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "status": "running",
    }
    error = None

    try:
        node.start("01-live-miner-address-switch", mode="miner", genesis=True)
        miner_pid = node.proc.pid
        address0 = active(node)
        require(int(address0["key_index"]) == 0, f"unexpected first address: {address0}")

        live.wait_mined(node, 1, timeout=900)
        payout0_h1 = wait_payout(node, 1, 0)

        address1 = rpc(node.rpc_port, "walletNextAddress")
        require(
            int(address1["key_index"]) == 1 and not address1["is_active"],
            f"new address did not remain inactive: {address1}",
        )
        require(active(node) == address0, "address creation changed the active payout")
        require(node.proc.pid == miner_pid, "address creation restarted the miner")
        listed_after_create = addresses(node)
        require(
            [int(item["key_index"]) for item in listed_after_create if item["is_active"]]
            == [0],
            f"wrong active marker after creation: {listed_after_create}",
        )

        live.wait_mined(node, 2, timeout=900)
        payout0_h2 = wait_payout(node, 2, 0)

        activated1 = rpc(node.rpc_port, "walletSetActiveAddress", [1], timeout=180)
        require(
            activated1["address"] == address1["address"] and activated1["is_active"],
            f"address 1 did not activate: {activated1}",
        )
        activation_tip = node.height()
        require(node.proc.pid == miner_pid, "USE restarted the miner process")

        next_height = activation_tip + 1
        live.wait_mined(node, next_height, timeout=900)
        payout1 = wait_payout(node, next_height, 1)
        require(active(node) == activated1, "mining changed the selected active address")

        # Repeated USE on the already-active address is an idempotent no-op.
        repeated = [
            rpc(node.rpc_port, "walletSetActiveAddress", [1], timeout=180)
            for _ in range(3)
        ]
        require(
            all(item == activated1 for item in repeated),
            f"idempotent USE changed address metadata: {repeated}",
        )
        repeated_tip = node.height()
        live.wait_mined(node, repeated_tip + 1, timeout=900)
        payout1_after_repeat = wait_payout(node, repeated_tip + 1, 1)

        log_text = (BASE / "logs" / "01-live-miner-address-switch.log").read_text(
            errors="replace"
        )
        live.assert_clean_log("wallet payout switch", log_text)

        summary.update(
            {
                "status": "passed",
                "miner_pid": miner_pid,
                "address0": address0,
                "address1": address1,
                "listed_after_create": listed_after_create,
                "payout_before_creation": payout0_h1,
                "payout_after_inactive_creation": payout0_h2,
                "activation_tip": activation_tip,
                "first_payout_after_use": payout1,
                "payout_after_repeated_use": payout1_after_repeat,
            }
        )
        print(
            "[PASS] inactive generation preserves payout; USE atomically redirects live mining",
            flush=True,
        )
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        try:
            stop_if_running(node)
        except Exception as cleanup_error:
            if error is None:
                error = cleanup_error
                summary["status"] = "failed"
                summary["error"] = str(cleanup_error)
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"[summary] {BASE / 'summary.json'}", flush=True)

    if error is not None:
        raise error


if __name__ == "__main__":
    main()
