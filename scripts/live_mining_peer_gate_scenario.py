#!/usr/bin/env python3
"""Live isolated-mining override and ordinary single-peer gate scenario."""

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
PEER_LOSS_HOLD_SECONDS = 25

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


def wait_mined_without_gate_drop(node, target, timeout=900):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        info = node.info()
        height = int(info["height"])
        if height != last:
            print(f"[continuous-mine] {node.name} height={height}/{target}", flush=True)
            last = height
        require(
            bool(node_status(node)["mining_ready"]),
            f"ordinary canonical child closed the mining gate at height {height}",
        )
        if height >= target:
            return info
        time.sleep(0.1)
    raise live.LiveForkReorgError(
        f"{node.name} did not continuously mine h{target}; last={last}"
    )


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    ports = tuple(BASE_PORT + offset for offset in (0, 1, 10, 11))
    for port in ports:
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)

    miner = Node("miner", BASE_PORT, BASE_PORT + 1)
    wallet_a = Node("wallet-a", BASE_PORT + 10, BASE_PORT + 11)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "no_peer_hold_seconds": NO_PEER_HOLD_SECONDS,
        "peer_loss_hold_seconds": PEER_LOSS_HOLD_SECONDS,
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
        shared_tip = live.wait_value(
            "ordinary wallet and miner share the canonical tip",
            lambda: exact_tip((miner, wallet_a)),
            timeout=180,
        )
        require(
            int(node_status(wallet_a)["mining"]) == 0,
            "the wallet peer unexpectedly runs a miner",
        )
        miner.stop()

        miner.start(
            "06-normal-miner-one-wallet-peer",
            mode="miner",
            seeds=[wallet_a.seed],
        )
        ready = live.wait_value(
            "one ordinary wallet peer opens the mining gate",
            lambda: normal_gate(miner, True),
            timeout=120,
        )
        require(
            int(ready["mining_confirmed_peers"])
            >= int(ready["mining_required_peers"])
            == 1,
            f"unexpected mining gate: {ready}",
        )
        normal_h3 = live.wait_mined(miner, 3, timeout=900)
        normal_h4 = wait_mined_without_gate_drop(miner, 4, timeout=900)

        wallet_a.stop()
        paused = live.wait_value(
            "losing the only wallet peer pauses normal mining",
            lambda: normal_gate(miner, False),
            timeout=60,
        )
        paused_height = miner.height()
        time.sleep(PEER_LOSS_HOLD_SECONDS)
        require(
            miner.height() == paused_height,
            "miner produced a block after losing its only network peer",
        )

        wallet_a.start("07-wallet-a-reconnect", seeds=[miner.seed])
        resumed = live.wait_value(
            "reconnected wallet peer restores mining",
            lambda: normal_gate(miner, True),
            timeout=120,
        )
        resumed_h5 = wait_mined_without_gate_drop(miner, 5, timeout=900)

        miner_log = miner.log_text()
        completed_proofs = {
            height: miner_log.count(f"mining complete block height={height}")
            for height in (3, 4, 5)
        }
        require(
            completed_proofs[3] == 1 and completed_proofs[4] == 1,
            f"unchanged frontier rebuilt a completed proof: {completed_proofs}",
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
                "ordinary_peer_gate": ready,
                "normal_mining_h3": normal_h3,
                "continuous_mining_h4": normal_h4,
                "after_peer_loss": paused,
                "paused_height": paused_height,
                "after_peer_reconnect": resumed,
                "resumed_mining_h5": resumed_h5,
                "completed_proofs": completed_proofs,
            }
        )
        print("[PASS] isolated override and ordinary single-peer mining gate", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        for node in (wallet_a, miner):
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
