#!/usr/bin/env python3
"""Fresh 128-transaction mempool competition between two production miners."""

import datetime
import json
import os
import re
import time
from collections import defaultdict
from pathlib import Path

import live_large_mempool_single_miner_scenario as shared


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_LARGE_MEMPOOL_TWO_DIR",
        str(RUN_PARENT / f"large-mempool-two-miners-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_LARGE_MEMPOOL_TWO_BASE_PORT", "21900"))

# The helper functions are pure RPC/log orchestration. Point both imported
# modules at this scenario's independent directory and ports before any Node is
# created. No chain or wallet data is shared with the single-miner run.
shared.BASE = BASE
shared.BASE_PORT = BASE_PORT
live = shared.live
live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def all_exact(nodes):
    infos = [node.info() for node in nodes]
    heights = {int(info["height"]) for info in infos}
    hashes = {info["best_hash"] for info in infos}
    if len(heights) == 1 and len(hashes) == 1:
        return {"height": heights.pop(), "hash": hashes.pop()}
    return False


def prepare_independent_utxos(funder, relay, phase_logs):
    relay_label = "01-setup-relay-fresh-h0"
    relay.start(relay_label)
    phase_logs.append(relay_label)

    bootstrap_label = "02-setup-funder-fresh-genesis-miner"
    funder.start(bootstrap_label, mode="miner", genesis=True, seeds=[relay.seed])
    phase_logs.append(bootstrap_label)
    live.wait_value(
        f"fresh setup reaches h{shared.INITIAL_HEIGHT}",
        lambda: funder.info()
        if funder.height() >= shared.INITIAL_HEIGHT
        else False,
        timeout=900,
    )
    live.wait_value(
        "setup relay matches funded prefix",
        lambda: shared.exact_tip(funder, relay),
        timeout=300,
    )
    funder.stop()

    node_label = "03-setup-funder-funded-node"
    funder.start(node_label, seeds=[relay.seed])
    phase_logs.append(node_label)
    live.wait_value(
        "setup funder reconnects",
        lambda: shared.exact_tip(funder, relay),
        timeout=180,
    )
    active = rpc(funder.rpc_port, "walletActiveAddress")
    rpc(funder.rpc_port, "walletScan", timeout=180)
    rounds = []

    for round_index, (count, amount) in enumerate(shared.SPLIT_ROUNDS, start=1):
        before = rpc(funder.rpc_port, "walletGetBalance")
        require(
            int(before["utxo_count"]) >= count,
            f"setup round {round_index} lacks inputs: {before}",
        )
        sends, submission_s = shared.submit_self_payments(
            funder, active["address"], count, amount
        )
        txids = [send["txid"] for send in sends]
        require(
            shared.exact_mempool(funder, txids) == count,
            f"setup round {round_index} local mempool mismatch",
        )
        live.wait_value(
            f"setup round {round_index} relays {count}",
            lambda txids=txids: shared.exact_mempool(relay, txids),
            timeout=180,
        )
        parent = funder.height()
        funder.stop()

        miner_label = f"04-setup-split-{round_index:02d}-miner"
        funder.start(miner_label, mode="miner", seeds=[relay.seed])
        phase_logs.append(miner_label)
        drained = shared.wait_round_drain(funder, relay, parent)
        confirmed = shared.fetch_confirmed(relay, txids)
        require(all(confirmed), f"setup round {round_index} lost a transaction")
        funder.stop()

        node_label = f"05-setup-split-{round_index:02d}-node"
        funder.start(node_label, seeds=[relay.seed])
        phase_logs.append(node_label)
        live.wait_value(
            f"setup round {round_index} returns on exact tip",
            lambda: shared.exact_tip(funder, relay),
            timeout=180,
        )
        after = rpc(funder.rpc_port, "walletGetBalance")
        require(
            int(after["utxo_count"]) >= count * 2,
            f"setup round {round_index} failed to grow UTXOs: {after}",
        )
        rounds.append(
            {
                "round": round_index,
                "submitted": count,
                "submission_s": round(submission_s, 3),
                "drained_tip": drained,
                "utxos_after": int(after["utxo_count"]),
            }
        )
        print(
            f"[setup-split] round={round_index} count={count} "
            f"utxos={after['utxo_count']}",
            flush=True,
        )

    balance = rpc(funder.rpc_port, "walletGetBalance")
    require(
        int(balance["utxo_count"]) >= shared.SPAM_COUNT,
        f"fresh setup produced too few UTXOs: {balance}",
    )
    return active, balance, rounds


def accepted_blocks(log):
    blocks = []
    for line in log.splitlines():
        if "block accepted" not in line:
            continue
        fields = {}
        for key in ("height", "txs", "pow_ms", "history_step_ms"):
            match = re.search(rf"(?:^|\s){key}=(\d+)(?:\s|$)", line)
            fields[key] = int(match.group(1)) if match else None
        blocks.append(fields)
    return blocks


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
    ports = (
        BASE_PORT,
        BASE_PORT + 1,
        BASE_PORT + 10,
        BASE_PORT + 11,
        BASE_PORT + 20,
        BASE_PORT + 21,
    )
    for port in ports:
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_LARGE_MEMPOOL_TWO_RUN").write_text(str(BASE) + "\n")

    funder = Node("funder", BASE_PORT, BASE_PORT + 1)
    miner_a = Node("miner-a", BASE_PORT + 10, BASE_PORT + 11)
    miner_b = Node("miner-b", BASE_PORT + 20, BASE_PORT + 21)
    nodes = (funder, miner_a, miner_b)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "spam_count": shared.SPAM_COUNT,
        "status": "running",
    }
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={summary['binary_sha256']} size={summary['binary_size']}",
        flush=True,
    )

    error = None
    cleanup = []
    phase_logs = []
    try:
        active, prepared_balance, split_rounds = prepare_independent_utxos(
            funder, miner_a, phase_logs
        )

        miner_b_label = "06-miner-b-fresh-sync-before-race"
        miner_b.start(miner_b_label, seeds=[funder.seed])
        phase_logs.append(miner_b_label)
        live.wait_value(
            "three setup nodes share one exact empty-mempool tip",
            lambda: all_exact(nodes)
            if all(int(rpc(node.rpc_port, "getMempoolSize")) == 0 for node in nodes)
            else False,
            timeout=600,
        )

        spam_sends, spam_submission_s = shared.submit_self_payments(
            funder,
            active["address"],
            shared.SPAM_COUNT,
            shared.SPAM_AMOUNT,
        )
        spam_txids = [send["txid"] for send in spam_sends]
        require(
            shared.exact_mempool(funder, spam_txids) == shared.SPAM_COUNT,
            "funder large mempool is not exact",
        )
        propagation_started = time.monotonic()
        live.wait_value(
            "miner-a node receives all 128 transactions",
            lambda: shared.exact_mempool(miner_a, spam_txids),
            timeout=300,
        )
        live.wait_value(
            "miner-b node receives all 128 transactions",
            lambda: shared.exact_mempool(miner_b, spam_txids),
            timeout=300,
        )
        propagation_s = time.monotonic() - propagation_started
        parent = funder.info()

        # Stop only the future miners. The connected funder retains the exact
        # 128-intent snapshot and serves it symmetrically when both miners
        # restart together on the same canonical parent.
        miner_a.request_stop()
        miner_b.request_stop()
        miner_a.finish_stop()
        miner_b.finish_stop()

        miner_a_label = "07-miner-a-races-128"
        miner_b_label = "08-miner-b-races-128"
        start_a = miner_a.spawn(miner_a_label, mode="miner", seeds=[funder.seed])
        start_b = miner_b.spawn(miner_b_label, mode="miner", seeds=[funder.seed])
        phase_logs.extend((miner_a_label, miner_b_label))
        _, startup_a = miner_a.wait_ready(miner_a_label, start_a, timeout=600)
        _, startup_b = miner_b.wait_ready(miner_b_label, start_b, timeout=600)

        max_pools = {node.name: 0 for node in nodes}
        samples = []
        last_sample = None
        race_started = time.monotonic()
        deadline = race_started + 2400
        while time.monotonic() < deadline:
            infos = {node.name: node.info() for node in nodes}
            pools = {
                node.name: int(rpc(node.rpc_port, "getMempoolSize")) for node in nodes
            }
            for name, size in pools.items():
                max_pools[name] = max(max_pools[name], size)
            sample = tuple(
                (node.name, int(infos[node.name]["height"]), pools[node.name])
                for node in nodes
            )
            if sample != last_sample:
                rendered = {
                    name: {"height": height, "mempool": pool}
                    for name, height, pool in sample
                }
                rendered["elapsed_s"] = round(time.monotonic() - race_started, 3)
                samples.append(rendered)
                print(f"[race] {rendered}", flush=True)
                last_sample = sample

            heights = {int(info["height"]) for info in infos.values()}
            hashes = {info["best_hash"] for info in infos.values()}
            if (
                all(size == 0 for size in pools.values())
                and len(heights) == 1
                and len(hashes) == 1
                and next(iter(heights)) > int(parent["height"])
            ):
                final_tip = {
                    "height": next(iter(heights)),
                    "hash": next(iter(hashes)),
                }
                break
            time.sleep(0.25)
        else:
            raise live.LiveForkReorgError(f"two-miner race did not converge: {samples[-12:]}")
        race_s = time.monotonic() - race_started

        confirmed = shared.fetch_confirmed(funder, spam_txids)
        require(all(confirmed), "canonical chain lost one or more raced transactions")
        by_height = defaultdict(list)
        for txid, location in zip(spam_txids, confirmed):
            by_height[int(location["height"])].append(
                (txid, int(location["tx_position"]))
            )
        distribution = {height: len(items) for height, items in sorted(by_height.items())}
        require(
            sorted(distribution.values()) == [64, 64],
            f"canonical B64 chain did not contain two full batches: {distribution}",
        )
        for height, items in by_height.items():
            positions = {position for _, position in items}
            require(
                positions == set(range(1, 65)),
                f"canonical tx positions at h{height} are incomplete",
            )

        log_a = text(miner_a_label)
        log_b = text(miner_b_label)
        attempts = {
            "miner-a": shared.parse_mined_blocks(log_a),
            "miner-b": shared.parse_mined_blocks(log_b),
        }
        accepted = {
            "miner-a": accepted_blocks(log_a),
            "miner-b": accepted_blocks(log_b),
        }
        for name, log in (("miner-a", log_a), ("miner-b", log_b)):
            require(
                re.search(r"mining template ready .*n_txs=65 .*max_user_pages=64", log)
                is not None,
                f"{name} never entered the full B64 race",
            )
            require(
                re.search(
                    rf"mempool sync: received pending TXs from peer.*\btx_count={shared.SPAM_COUNT}\b",
                    log,
                )
                is not None,
                f"{name} did not receive the exact 128-intent snapshot",
            )
        require(
            sum(len(blocks) for blocks in accepted.values()) >= 2,
            f"miners accepted too few blocks: {accepted}",
        )

        for label in phase_logs:
            shared.assert_clean(label, text(label))

        summary.update(
            {
                "status": "passed",
                "active_address": active,
                "prepared_balance": prepared_balance,
                "split_rounds": split_rounds,
                "spam_submission_s": round(spam_submission_s, 3),
                "propagation_s": round(propagation_s, 3),
                "miner_startup_s": {
                    "miner-a": round(startup_a, 3),
                    "miner-b": round(startup_b, 3),
                },
                "race_s": round(race_s, 3),
                "max_mempools": max_pools,
                "race_samples": samples,
                "final_tip": final_tip,
                "confirmation_distribution": distribution,
                "mining_attempts": attempts,
                "accepted_blocks": accepted,
            }
        )
        print(
            f"[PASS] two miners converged after racing 128 TXs: {distribution}",
            flush=True,
        )
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
