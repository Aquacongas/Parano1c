#!/usr/bin/env python3
"""Fresh 128-transaction mempool drain by one production B64 miner.

The setup grows independent wallet UTXOs through confirmed self-splits; no
saved chain fixture or debug-only node path is used.  Mining is then stopped,
128 non-conflicting one-page transactions are admitted and relayed, and a
single miner must drain them without loss.  On the baseline laptop the
expected production shape is two 64-user-page B64 blocks.
"""

import datetime
import json
import os
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_LARGE_MEMPOOL_SINGLE_DIR",
        str(RUN_PARENT / f"large-mempool-single-miner-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_LARGE_MEMPOOL_SINGLE_BASE_PORT", "21800"))
INITIAL_HEIGHT = 4
SPAM_COUNT = 128
SPAM_AMOUNT = 100_000
SPLIT_ROUNDS = (
    (4, 20_000_000),
    (8, 9_000_000),
    (16, 4_000_000),
    (32, 1_500_000),
    (64, 500_000),
)

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


def mempool_txids(node):
    info = rpc(node.rpc_port, "getMempoolInfo")
    return info, {entry["tx_hash"] for entry in info["txs"]}


def exact_mempool(node, txids):
    info, found = mempool_txids(node)
    if int(info["size"]) == len(txids) and found == set(txids):
        return int(info["size"])
    return False


def submit_self_payments(node, address, count, amount):
    started = time.monotonic()
    sends = []
    for index in range(count):
        sent = rpc(
            node.rpc_port,
            "walletSend",
            [address, amount, 0],
            timeout=300,
        )
        require(sent["input_count"] == 1, f"send {index} is not one-input: {sent}")
        require(sent["output_count"] == 2, f"send {index} lost change: {sent}")
        sends.append(sent)
        if (index + 1) % 16 == 0 or index + 1 == count:
            print(f"[submit] {index + 1}/{count}", flush=True)
    txids = [sent["txid"] for sent in sends]
    require(len(set(txids)) == count, "wallet produced duplicate transaction IDs")
    return sends, time.monotonic() - started


def fetch_confirmed(node, txids):
    return [rpc(node.rpc_port, "getTx", [txid]) for txid in txids]


def wait_round_drain(miner, relay, parent_height, timeout=900):
    def drained():
        miner_info = miner.info()
        relay_info = relay.info()
        miner_pool = int(rpc(miner.rpc_port, "getMempoolSize"))
        relay_pool = int(rpc(relay.rpc_port, "getMempoolSize"))
        if (
            int(miner_info["height"]) > parent_height
            and int(relay_info["height"]) == int(miner_info["height"])
            and relay_info["best_hash"] == miner_info["best_hash"]
            and miner_pool == 0
            and relay_pool == 0
        ):
            return {
                "height": int(miner_info["height"]),
                "hash": miner_info["best_hash"],
            }
        return False

    return live.wait_value("round mempools drain on one exact tip", drained, timeout=timeout)


def parse_mined_blocks(text):
    blocks = []
    for line in text.splitlines():
        if "mining complete block" not in line:
            continue
        fields = {}
        for key in ("height", "txs", "user_pages", "prepare_ms"):
            match = re.search(rf"(?:^|\s){key}=(\d+)(?:\s|$)", line)
            fields[key] = int(match.group(1)) if match else None
        class_match = re.search(r"(?:^|\s)proof_class=([A-Za-z0-9]+)(?:\s|$)", line)
        fields["proof_class"] = class_match.group(1) if class_match else None
        blocks.append(fields)
    return blocks


def log_text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


FAILURE_MARKERS = (
    " ERROR ",
    "panicked",
    "P2P network error",
    "P2P block rejected",
    "wallet proof task",
    "wallet builder diverged",
    "mempool relay: lagged",
    "tx rejected",
    "mempool sync: tx rejected",
)


def assert_clean(label, text):
    failures = [
        line
        for line in text.splitlines()
        if any(marker in line for marker in FAILURE_MARKERS)
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
    (RUN_PARENT / "LAST_LARGE_MEMPOOL_SINGLE_RUN").write_text(str(BASE) + "\n")

    funder = Node("funder", BASE_PORT, BASE_PORT + 1)
    relay = Node("relay-then-miner", BASE_PORT + 10, BASE_PORT + 11)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "binary_size": live.NODE_BIN.stat().st_size,
        "spam_count": SPAM_COUNT,
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
    split_summaries = []
    try:
        relay_label = "01-relay-fresh-h0"
        relay.start(relay_label)
        phase_logs.append(relay_label)

        bootstrap_label = "02-funder-fresh-genesis-miner"
        funder.start(bootstrap_label, mode="miner", genesis=True, seeds=[relay.seed])
        phase_logs.append(bootstrap_label)
        live.wait_value(
            f"fresh chain reaches h{INITIAL_HEIGHT}",
            lambda: funder.info() if funder.height() >= INITIAL_HEIGHT else False,
            timeout=900,
        )
        live.wait_value(
            "relay matches funded prefix",
            lambda: exact_tip(funder, relay),
            timeout=300,
        )
        funder.stop()

        funder_node_label = "03-funder-funded-node"
        funder.start(funder_node_label, seeds=[relay.seed])
        phase_logs.append(funder_node_label)
        live.wait_value("funded node reconnects", lambda: exact_tip(funder, relay), timeout=180)
        active = rpc(funder.rpc_port, "walletActiveAddress")
        rpc(funder.rpc_port, "walletScan", timeout=180)

        for round_index, (count, amount) in enumerate(SPLIT_ROUNDS, start=1):
            balance_before = rpc(funder.rpc_port, "walletGetBalance")
            require(
                int(balance_before["utxo_count"]) >= count,
                f"split round {round_index} lacks {count} inputs: {balance_before}",
            )
            sends, submit_seconds = submit_self_payments(
                funder, active["address"], count, amount
            )
            txids = [send["txid"] for send in sends]
            require(
                exact_mempool(funder, txids) == count,
                f"split round {round_index} local mempool is not exact",
            )
            live.wait_value(
                f"split round {round_index} relays all {count} transactions",
                lambda txids=txids: exact_mempool(relay, txids),
                timeout=180,
            )
            parent_height = funder.height()
            funder.stop()

            miner_label = f"04-split-{round_index:02d}-funder-miner"
            funder.start(miner_label, mode="miner", seeds=[relay.seed])
            phase_logs.append(miner_label)
            drained = wait_round_drain(funder, relay, parent_height)
            confirmed = fetch_confirmed(relay, txids)
            require(all(confirmed), f"split round {round_index} lost confirmations")
            confirmation_heights = sorted({int(item["height"]) for item in confirmed})
            funder.stop()

            node_label = f"05-split-{round_index:02d}-funder-node"
            funder.start(node_label, seeds=[relay.seed])
            phase_logs.append(node_label)
            live.wait_value(
                f"split round {round_index} node returns on exact tip",
                lambda: exact_tip(funder, relay),
                timeout=180,
            )
            balance_after = rpc(funder.rpc_port, "walletGetBalance")
            require(
                int(balance_after["utxo_count"]) >= count * 2,
                f"split round {round_index} did not grow UTXOs: {balance_after}",
            )
            split_summaries.append(
                {
                    "round": round_index,
                    "submitted": count,
                    "amount_micronoid": amount,
                    "submission_s": round(submit_seconds, 3),
                    "confirmation_heights": confirmation_heights,
                    "drained_tip": drained,
                    "utxos_before": int(balance_before["utxo_count"]),
                    "utxos_after": int(balance_after["utxo_count"]),
                }
            )
            print(
                f"[split] round={round_index} count={count} "
                f"utxos={balance_after['utxo_count']}",
                flush=True,
            )

        prepared_balance = rpc(funder.rpc_port, "walletGetBalance")
        require(
            int(prepared_balance["utxo_count"]) >= SPAM_COUNT,
            f"setup produced too few independent UTXOs: {prepared_balance}",
        )

        spam_sends, spam_submission_seconds = submit_self_payments(
            funder, active["address"], SPAM_COUNT, SPAM_AMOUNT
        )
        spam_txids = [send["txid"] for send in spam_sends]
        require(
            exact_mempool(funder, spam_txids) == SPAM_COUNT,
            "funder does not hold the exact large mempool",
        )
        relay_propagation_started = time.monotonic()
        live.wait_value(
            "all 128 transactions reach relay mempool",
            lambda: exact_mempool(relay, spam_txids),
            timeout=300,
        )
        relay_propagation_seconds = time.monotonic() - relay_propagation_started
        spam_parent = funder.info()
        relay.stop()

        final_miner_label = "06-single-miner-drains-128"
        relay.start(final_miner_label, mode="miner", seeds=[funder.seed])
        phase_logs.append(final_miner_label)
        max_miner_pool = 0
        max_funder_pool = SPAM_COUNT
        samples = []
        last_sample = None
        drain_started = time.monotonic()
        deadline = drain_started + 1800
        while time.monotonic() < deadline:
            miner_info = relay.info()
            funder_info = funder.info()
            miner_pool = int(rpc(relay.rpc_port, "getMempoolSize"))
            funder_pool = int(rpc(funder.rpc_port, "getMempoolSize"))
            max_miner_pool = max(max_miner_pool, miner_pool)
            max_funder_pool = max(max_funder_pool, funder_pool)
            sample = (
                int(miner_info["height"]),
                miner_pool,
                int(funder_info["height"]),
                funder_pool,
            )
            if sample != last_sample:
                samples.append(
                    {
                        "elapsed_s": round(time.monotonic() - drain_started, 3),
                        "miner_height": sample[0],
                        "miner_mempool": sample[1],
                        "funder_height": sample[2],
                        "funder_mempool": sample[3],
                    }
                )
                print(f"[drain] {samples[-1]}", flush=True)
                last_sample = sample
            if (
                miner_pool == 0
                and funder_pool == 0
                and int(miner_info["height"]) > int(spam_parent["height"])
                and int(funder_info["height"]) == int(miner_info["height"])
                and funder_info["best_hash"] == miner_info["best_hash"]
            ):
                break
            time.sleep(0.25)
        else:
            raise live.LiveForkReorgError(f"large mempool did not drain: {samples[-10:]}")
        drain_seconds = time.monotonic() - drain_started

        confirmed = fetch_confirmed(funder, spam_txids)
        require(all(confirmed), "one or more spam transactions disappeared instead of confirming")
        by_height = defaultdict(list)
        for txid, location in zip(spam_txids, confirmed):
            by_height[int(location["height"])].append((txid, int(location["tx_position"])))
        distribution = {height: len(items) for height, items in sorted(by_height.items())}
        require(sum(distribution.values()) == SPAM_COUNT, f"confirmation count mismatch: {distribution}")
        require(
            all(count <= 64 for count in distribution.values()),
            f"B64 miner exceeded 64 user transactions: {distribution}",
        )
        require(
            sorted(distribution.values()) == [64, 64],
            f"single B64 miner failed to use two full blocks: {distribution}",
        )
        for height, items in by_height.items():
            positions = {position for _, position in items}
            require(
                positions == set(range(1, len(items) + 1)),
                f"non-contiguous logical positions at h{height}: {sorted(positions)}",
            )

        final_miner_text = log_text(final_miner_label)
        mined_blocks = parse_mined_blocks(final_miner_text)
        full_blocks = [block for block in mined_blocks if block["user_pages"] == 64]
        require(len(full_blocks) >= 2, f"miner log lacks two full B64 blocks: {mined_blocks}")
        require(
            all(block["proof_class"] == "B64" for block in full_blocks),
            f"64-page blocks used the wrong proof class: {full_blocks}",
        )
        require(
            re.search(
                rf"mempool sync: received pending TXs from peer.*\btx_count={SPAM_COUNT}\b",
                final_miner_text,
            )
            is not None,
            "single miner did not receive the exact 128-transaction peer snapshot",
        )

        for label in phase_logs:
            assert_clean(label, log_text(label))

        summary.update(
            {
                "status": "passed",
                "initial_height": INITIAL_HEIGHT,
                "active_address": active,
                "split_rounds": split_summaries,
                "prepared_balance": prepared_balance,
                "spam_submission_s": round(spam_submission_seconds, 3),
                "relay_propagation_s": round(relay_propagation_seconds, 3),
                "drain_s": round(drain_seconds, 3),
                "max_miner_mempool": max_miner_pool,
                "max_funder_mempool": max_funder_pool,
                "drain_samples": samples,
                "confirmation_distribution": distribution,
                "mining_blocks": mined_blocks,
                "fee_counts": dict(Counter(send["fee_micronoid"] for send in spam_sends)),
            }
        )
        print(f"[PASS] one B64 miner drained 128 TXs as {distribution}", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        stop_if_running(relay, cleanup)
        stop_if_running(funder, cleanup)
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
