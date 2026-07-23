#!/usr/bin/env python3
"""Live isolated-mining override and ordinary-peer quorum scenario."""

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
        "NOID_LIVE_MINING_GATE_DIR",
        str(RUN_PARENT / f"mining-peer-gate-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_MINING_GATE_BASE_PORT", "23600"))
NO_PEER_HOLD_SECONDS = 35

live.BASE = BASE
Node = live.Node
rpc = live.rpc
require = live.require


def node_status(node):
    return rpc(node.rpc_port, "getNodeStatus")


def exact_tip(nodes):
    tips = [node.info() for node in nodes]
    first = tips[0]
    if all(
        int(tip["height"]) == int(first["height"])
        and tip["best_hash"] == first["best_hash"]
        for tip in tips[1:]
    ):
        return {
            "height": int(first["height"]),
            "hash": first["best_hash"],
        }
    return False


def normal_gate(node, ready):
    status = node_status(node)
    if (
        bool(status["mining_ready"]) is ready
        and not bool(status["isolated_mining"])
    ):
        return status
    return False


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    ports = tuple(BASE_PORT + offset for offset in (0, 1, 10, 11, 20, 21))
    for port in ports:
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)

    miner = Node("miner", BASE_PORT, BASE_PORT + 1)
    wallet_a = Node("wallet-a", BASE_PORT + 10, BASE_PORT + 11)
    wallet_b = Node("wallet-b", BASE_PORT + 20, BASE_PORT + 21)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "no_peer_hold_seconds": NO_PEER_HOLD_SECONDS,
        "status": "running",
    }
    error = None

    try:
        miner.start("01-normal-miner-no-peers", mode="miner")
        waiting = live.wait_value(
            "normal miner waits without peers",
            lambda: normal_gate(miner, False),
            timeout=30,
        )
        held_height = miner.height()
        time.sleep(NO_PEER_HOLD_SECONDS)
        require(
            miner.height() == held_height,
            "normal miner produced a block without a peer quorum",
        )
        miner.stop()

        miner.start("02-isolated-miner-h1", mode="miner", genesis=True)
        isolated_h1 = live.wait_mined(miner, 1, timeout=900)
        miner.stop()

        restart_info, _ = miner.start(
            "03-isolated-restart-h2",
            mode="miner",
            genesis=True,
        )
        require(
            int(restart_info["height"]) >= 1,
            f"isolated restart lost the existing chain: {restart_info}",
        )
        isolated_h2 = live.wait_mined(miner, 2, timeout=900)
        miner.stop()

        miner.start("04-prefix-server")
        wallet_a.start("05-wallet-a-sync", seeds=[miner.seed])
        wallet_b.start("06-wallet-b-sync", seeds=[miner.seed])
        shared_tip = live.wait_value(
            "two ordinary wallet nodes share the canonical tip",
            lambda: exact_tip((miner, wallet_a, wallet_b)),
            timeout=180,
        )
        require(
            int(node_status(wallet_a)["mining"]) == 0
            and int(node_status(wallet_b)["mining"]) == 0,
            "a quorum peer unexpectedly runs a miner",
        )
        miner.stop()

        miner.start(
            "07-normal-miner-two-wallet-peers",
            mode="miner",
            seeds=[wallet_a.seed, wallet_b.seed],
        )
        ready = live.wait_value(
            "two ordinary wallet peers open the mining gate",
            lambda: normal_gate(miner, True),
            timeout=120,
        )
        require(
            int(ready["mining_confirmed_peers"])
            >= int(ready["mining_required_peers"])
            == 2,
            f"unexpected mining quorum: {ready}",
        )
        normal_h3 = live.wait_mined(miner, 3, timeout=900)

        wallet_b.stop()
        paused = live.wait_value(
            "losing one wallet peer pauses normal mining",
            lambda: normal_gate(miner, False),
            timeout=60,
        )

        wallet_b.start("08-wallet-b-reconnect", seeds=[miner.seed])
        resumed = live.wait_value(
            "reconnected wallet peer restores the quorum",
            lambda: normal_gate(miner, True),
            timeout=120,
        )

        for log_path in sorted((BASE / "logs").glob("*.log")):
            live.assert_clean_log(
                log_path.stem,
                log_path.read_text(errors="replace"),
            )

        summary.update(
            {
                "status": "passed",
                "no_peer_status": waiting,
                "isolated_h1": isolated_h1,
                "isolated_restart_h2": isolated_h2,
                "shared_tip": shared_tip,
                "ordinary_peer_quorum": ready,
                "normal_mining_h3": normal_h3,
                "after_peer_loss": paused,
                "after_peer_reconnect": resumed,
            }
        )
        print("[PASS] isolated override and ordinary-peer mining quorum", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        for node in (wallet_b, wallet_a, miner):
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
