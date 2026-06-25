#!/usr/bin/env python3
# pyright: reportMissingParameterType=false, reportUnknownParameterType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportAny=false
"""Live multi-node Sweep25x2 / mixed-shape propagation scenario.

Covers:
- 3-node sync with one miner and two relays started before funding blocks;
- Sweep25x2 walletSend enters mempools, gossips, confirms, and converges;
- optionally, fragmented split send submits mixed chunks (Sweep25x2 + Standard4x8) and confirms;
- recipient wallet balance increases by the sent amount without explicit post-confirmation rescan.

Environment knobs:
  NOID_LIVE_MULTI_SWEEP_START_BLOCKS default 20, raised to at least 30 when split is enabled
  NOID_LIVE_MULTI_SWEEP_BASE_PORT    default 19900
  NOID_LIVE_MULTI_SWEEP_SKIP_SPLIT         default 1 (set 0 to run the heavier >25-input split scenario)
  NOID_LIVE_MULTI_SWEEP_RESTART            default 0 (restart sender+recipient after Sweep25x2)
  NOID_LIVE_MULTI_SWEEP_RESTART_RECIPIENT  defaults to restart flag
  NOID_LIVE_MULTI_SWEEP_RESTART_SENDER     defaults to restart flag
  NOID_LIVE_MULTI_SWEEP_RESTART_SPLIT      defaults to restart flag; only runs when split is enabled
"""

import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE_BIN = ROOT / "target" / "release" / "paranoid"
BASE = ROOT / "target" / "live-tests" / "multinode-sweep-shape"
LOGS = BASE / "logs"

START_BLOCKS = int(os.environ.get("NOID_LIVE_MULTI_SWEEP_START_BLOCKS", "20"))
BASE_PORT = int(os.environ.get("NOID_LIVE_MULTI_SWEEP_BASE_PORT", "19900"))
SKIP_SPLIT = os.environ.get("NOID_LIVE_MULTI_SWEEP_SKIP_SPLIT", "1") == "1"
if not SKIP_SPLIT:
    START_BLOCKS = max(START_BLOCKS, 30)
RESTART_ALL = os.environ.get("NOID_LIVE_MULTI_SWEEP_RESTART", "0") == "1"
RESTART_RECIPIENT = (
    os.environ.get(
        "NOID_LIVE_MULTI_SWEEP_RESTART_RECIPIENT", "1" if RESTART_ALL else "0"
    )
    == "1"
)
RESTART_SENDER = (
    os.environ.get(
        "NOID_LIVE_MULTI_SWEEP_RESTART_SENDER", "1" if RESTART_ALL else "0"
    )
    == "1"
)
RESTART_SPLIT = (
    os.environ.get(
        "NOID_LIVE_MULTI_SWEEP_RESTART_SPLIT", "1" if RESTART_ALL else "0"
    )
    == "1"
)


class LiveTestError(Exception):
    pass


class Node:
    def __init__(
        self,
        name,
        p2p_port,
        rpc_port,
        mode="relay",
        genesis=False,
        seed=None,
        log="info",
    ):
        self.name = name
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.mode = mode
        self.genesis = genesis
        self.seed = seed or []
        self.log = log
        self.data_dir = BASE / name
        self.log_path = LOGS / f"{name}.log"
        self.proc = None
        self.log_file = None

    @property
    def rpc_url(self):
        return f"http://127.0.0.1:{self.rpc_port}"

    @property
    def seed_addr(self):
        return f"127.0.0.1:{self.p2p_port}"

    def start(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        LOGS.mkdir(parents=True, exist_ok=True)
        args = [
            str(NODE_BIN),
            "--mode",
            self.mode,
            "--data-dir",
            str(self.data_dir),
            "--p2p-listen",
            f"127.0.0.1:{self.p2p_port}",
            "--rpc-listen",
            f"127.0.0.1:{self.rpc_port}",
            "--log",
            self.log,
        ]
        if self.genesis:
            args.append("--genesis")
        for seed in self.seed:
            args.extend(["--seed", seed])
        self.log_file = open(self.log_path, "ab", buffering=0)
        self.log_file.write(
            f"\n\n===== START {self.name} {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n".encode()
        )
        self.proc = subprocess.Popen(
            args, cwd=ROOT, stdout=self.log_file, stderr=subprocess.STDOUT
        )
        print(
            f"[start] {self.name}: pid={self.proc.pid} rpc={self.rpc_url} p2p={self.seed_addr} mode={self.mode} seeds={self.seed}",
            flush=True,
        )
        self.wait_rpc()

    def wait_rpc(self, timeout=60):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise LiveTestError(
                    f"{self.name} exited early code={self.proc.returncode}"
                )
            try:
                rpc(self.rpc_url, "getChainInfo", timeout=2)
                return
            except Exception as e:
                last = e
                time.sleep(0.5)
        raise LiveTestError(f"{self.name} RPC not ready: {last}")

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return
        print(f"[stop] {self.name}", flush=True)
        try:
            rpc(self.rpc_url, "stop", timeout=3)
        except Exception as e:
            print(f"[stop] {self.name}: rpc stop failed: {e}", flush=True)
        try:
            self.proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=6)
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def info(self):
        return rpc(self.rpc_url, "getChainInfo", timeout=10)

    def height(self):
        return int(self.info()["height"])

    def peers(self):
        return int(rpc(self.rpc_url, "getPeerCount", timeout=10))

    def mempool_size(self):
        return int(rpc(self.rpc_url, "getMempoolSize", timeout=10))

    def balance(self):
        return rpc(self.rpc_url, "walletGetBalance", timeout=20)

    def status(self):
        return rpc(self.rpc_url, "walletStatus", timeout=20)

    def address(self):
        return self.status()["address"]

    def utxos(self):
        return rpc(self.rpc_url, "walletListUtxos", timeout=20)


def rpc(url, method, params=None, timeout=8):
    method_full = method if method.startswith("paranoid_") else f"paranoid_{method}"
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method_full, "params": params or []}
    ).encode()
    req = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    if "error" in payload:
        raise LiveTestError(f"RPC {method} error: {payload['error']}")
    return payload.get("result")


def wait_until(desc, predicate, timeout=120, interval=1.0):
    print(f"[wait] {desc} timeout={timeout}s", flush=True)
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                print(f"[ok] {desc}: {value}", flush=True)
                return value
            last = value
        except Exception as e:
            last = e
        time.sleep(interval)
    raise LiveTestError(f"timeout waiting for {desc}; last={last}")


def assert_true(cond, msg):
    if not cond:
        raise LiveTestError(msg)


def same_tip(nodes, max_lag=0):
    infos = {n.name: n.info() for n in nodes}
    heights = [int(i["height"]) for i in infos.values()]
    hashes = [i["best_hash"] for i in infos.values()]
    if max(heights) - min(heights) > max_lag:
        return False
    if max_lag == 0 and len(set(hashes)) != 1:
        return False
    return {k: (v["height"], v["best_hash"][:12]) for k, v in infos.items()}


def tail(path, n=180):
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-n:])
    except Exception as e:
        return f"<cannot read {path}: {e}>"


def cleanup(nodes):
    for n in reversed(nodes):
        try:
            n.stop()
        except Exception as e:
            print(f"[cleanup] {n.name}: {e}", flush=True)


def choose_amount_requiring_inputs(utxos, min_inputs, fee_margin=100_000):
    values = sorted((int(u["value_micronoid"]) for u in utxos), reverse=True)
    if len(values) < min_inputs:
        raise LiveTestError(f"need at least {min_inputs} UTXOs, have {len(values)}")
    amount = sum(values[: min_inputs - 1]) + 1
    available = sum(values[: min(25, len(values))])
    if amount + fee_margin > available:
        raise LiveTestError(
            f"not enough value to force {min_inputs} inputs: amount={amount} available25={available}"
        )
    return amount


def choose_split_amount(utxos, fee_margin=500_000):
    values = sorted((int(u["value_micronoid"]) for u in utxos), reverse=True)
    if len(values) <= 25:
        raise LiveTestError(f"need >25 UTXOs for split scenario, have {len(values)}")
    amount = sum(values[:25]) + 1
    if amount + fee_margin > sum(values):
        raise LiveTestError(
            f"not enough value to force split: amount={amount} total={sum(values)}"
        )
    return amount


def any_confirmed(nodes, tx_hash):
    return any(rpc(n.rpc_url, "getTx", [tx_hash], timeout=10) for n in nodes)


def all_confirmed(nodes, tx_hash):
    return all(
        rpc(n.rpc_url, "getTx", [tx_hash], timeout=10) is not None for n in nodes
    )


def mempool_entries(nodes, tx_hashes):
    out = {}
    for n in nodes:
        out[n.name] = [
            rpc(n.rpc_url, "getMempoolEntry", [h], timeout=10) for h in tx_hashes
        ]
    return out


def history_hashes(node):
    return {h.get("tx_hash") for h in rpc(node.rpc_url, "walletHistory", timeout=20)}


def restart_and_assert_wallet(
    nodes,
    node,
    label,
    tx_hashes,
    min_total=None,
    max_utxo_growth_per_block=False,
):
    print(f"\n=== Restart {node.name} after {label} ===", flush=True)
    before_info = node.info()
    before_balance = node.balance()
    before_utxo_count = len(node.utxos())
    before_height = int(before_info["height"])
    expected_tip = before_info["best_hash"]

    node.stop()
    node.start()
    wait_until(
        f"{node.name} restarted node has peers",
        lambda: node.peers() if node.peers() >= 1 else False,
        timeout=120,
        interval=2,
    )
    wait_until(
        f"{node.name} reconverges after restart",
        lambda: same_tip(nodes, max_lag=0),
        timeout=300,
        interval=4,
    )

    after_info = node.info()
    after_balance = node.balance()
    after_height = int(after_info["height"])
    after_utxo_count = len(node.utxos())
    expected_min_total = (
        int(before_balance["total_micronoid"]) if min_total is None else min_total
    )

    assert_true(
        int(after_balance["total_micronoid"]) >= expected_min_total,
        f"{node.name}: balance regressed after restart: before={before_balance} after={after_balance}",
    )
    assert_true(
        int(after_balance["pending_outbound_micronoid"]) == 0,
        f"{node.name}: pending outbound not clear after restart: {after_balance}",
    )
    seen = history_hashes(node)
    assert_true(
        all(h in seen for h in tx_hashes),
        f"{node.name}: wallet history missing txs after restart {tx_hashes}: {seen}",
    )
    if max_utxo_growth_per_block:
        allowed = before_utxo_count + max(0, after_height - before_height)
        assert_true(
            after_utxo_count <= allowed,
            f"{node.name}: UTXOs grew too much after restart; before_count={before_utxo_count} after_count={after_utxo_count} expected_tip={expected_tip} after_info={after_info}",
        )
    else:
        assert_true(
            after_utxo_count == before_utxo_count,
            f"{node.name}: UTXO count changed across restart; before_count={before_utxo_count} after_count={after_utxo_count}",
        )
    print(
        f"[restart ok] {node.name}: balance={after_balance} utxos={before_utxo_count}->{after_utxo_count} tip={after_info}",
        flush=True,
    )


def wait_tx_gossiped_or_confirmed(nodes, tx_hashes, label):
    def pred():
        entries = mempool_entries(nodes, tx_hashes)
        present_counts = [
            sum(1 for n in nodes if entries[n.name][i] is not None)
            for i in range(len(tx_hashes))
        ]
        confirmed = [any_confirmed(nodes, h) for h in tx_hashes]
        if all(c >= 2 or confirmed[i] for i, c in enumerate(present_counts)):
            return {"present_counts": present_counts, "confirmed": confirmed}
        return False

    return wait_until(
        f"{label} gossiped to >=2 mempools or confirmed", pred, timeout=180, interval=2
    )


def wait_tx_confirmed_everywhere(nodes, tx_hashes, label):
    for h in tx_hashes:
        wait_until(
            f"{label} {h[:12]} confirmed somewhere",
            lambda h=h: any_confirmed(nodes, h),
            timeout=720,
            interval=4,
        )
        wait_until(
            f"{label} {h[:12]} confirmed on all nodes",
            lambda h=h: all_confirmed(nodes, h),
            timeout=240,
            interval=3,
        )


def send_and_confirm(
    nodes, sender, recipient, amount, label, expect_sweep=True, expect_split=False
):
    print(
        f"\n=== {label}: {sender.name} -> {recipient.name} amount={amount} ===",
        flush=True,
    )
    pre_recipient_balance = recipient.balance()
    pre_recipient = int(pre_recipient_balance["total_micronoid"])
    send = rpc(
        sender.rpc_url, "walletSend", [recipient.address(), amount, 0], timeout=360
    )
    print(f"[send] {json.dumps(send, indent=2)}", flush=True)
    tx_hashes = send.get("tx_hashes") or [send["tx_hash"]]
    tx_shapes = send.get("tx_shapes") or []
    assert_true(len(tx_hashes) == len(tx_shapes), f"tx shape/hash mismatch: {send}")
    if expect_sweep:
        assert_true("Sweep25x2" in tx_shapes, f"expected Sweep25x2 chunk: {send}")
    if expect_split:
        assert_true(
            int(send.get("split_count") or 1) > 1, f"expected split send: {send}"
        )
        assert_true(
            "Sweep25x2" in tx_shapes and "Standard4x8" in tx_shapes,
            f"expected mixed split shapes: {send}",
        )

    wait_tx_gossiped_or_confirmed(nodes, tx_hashes, label)
    entries = mempool_entries(nodes, tx_hashes)
    print(f"[mempool entries] {json.dumps(entries, indent=2)}", flush=True)
    wait_tx_confirmed_everywhere(nodes, tx_hashes, label)
    wait_until(
        f"{label} mempools drain",
        lambda: (
            {n.name: n.mempool_size() for n in nodes}
            if all(n.mempool_size() == 0 for n in nodes)
            else False
        ),
        timeout=300,
        interval=3,
    )
    wait_until(
        f"{label} chain convergence",
        lambda: same_tip(nodes, max_lag=0),
        timeout=300,
        interval=4,
    )
    post_recipient_balance = wait_until(
        f"{label} recipient received coins without rescan",
        lambda: (
            balance
            if int((balance := recipient.balance())["total_micronoid"])
            >= pre_recipient + amount
            else False
        ),
        timeout=180,
        interval=3,
    )
    received_delta = int(post_recipient_balance["total_micronoid"]) - pre_recipient
    assert_true(
        received_delta >= amount,
        f"recipient did not receive requested amount: before={pre_recipient_balance} after={post_recipient_balance} amount={amount}",
    )
    print(
        f"[recipient received] {recipient.name}: delta={received_delta} amount={amount} balance={post_recipient_balance}",
        flush=True,
    )
    send["recipient_received_delta"] = received_delta
    send["recipient_balance_before"] = pre_recipient_balance
    send["recipient_balance_after"] = post_recipient_balance
    return send


def main():
    if not NODE_BIN.exists():
        raise LiveTestError(
            f"release binary missing: {NODE_BIN}; run cargo build --release -p noid_node --bin paranoid"
        )
    if BASE.exists():
        shutil.rmtree(BASE)
    LOGS.mkdir(parents=True, exist_ok=True)

    n1 = Node("node1-sweep-miner", BASE_PORT, BASE_PORT + 1, mode="miner", genesis=True)
    n2 = Node("node2-sweep-relay", BASE_PORT + 10, BASE_PORT + 11, seed=[n1.seed_addr])
    n3 = Node(
        "node3-sweep-relay",
        BASE_PORT + 20,
        BASE_PORT + 21,
        seed=[n1.seed_addr, n2.seed_addr],
    )
    nodes = [n1, n2, n3]
    started = []

    try:
        print(
            "\n=== Multi-node sweep: start miner and relays before funding blocks ===",
            flush=True,
        )
        n1.start()
        started.append(n1)
        n2.start()
        started.append(n2)
        n3.start()
        started.append(n3)

        wait_until(
            "relays have peers",
            lambda: (
                {n.name: n.peers() for n in nodes}
                if n2.peers() >= 1 and n3.peers() >= 1
                else False
            ),
            timeout=120,
            interval=2,
        )
        wait_until(
            f"node1 mines {START_BLOCKS} funding blocks",
            lambda: n1.height() if n1.height() >= START_BLOCKS else False,
            timeout=max(900, START_BLOCKS * 35),
            interval=3,
        )
        wait_until(
            "all nodes converge after funding blocks",
            lambda: same_tip(nodes, max_lag=0),
            timeout=420,
            interval=4,
        )
        scan = rpc(n1.rpc_url, "walletScan", timeout=240)
        print(f"[scan node1] {scan}", flush=True)
        assert_true(
            len(n1.utxos()) >= 5, f"node1 needs >=5 UTXOs, has {len(n1.utxos())}"
        )
        print(f"[addresses] n2={n2.address()} n3={n3.address()}", flush=True)

        sweep_amount = choose_amount_requiring_inputs(n1.utxos(), 5)
        sweep_send = send_and_confirm(
            nodes, n1, n2, sweep_amount, "multi-node Sweep25x2", expect_sweep=True
        )

        sweep_tx_hashes = sweep_send.get("tx_hashes") or [sweep_send["tx_hash"]]
        if RESTART_RECIPIENT:
            restart_and_assert_wallet(
                nodes,
                n2,
                "confirmed Sweep25x2 recipient state",
                sweep_tx_hashes,
                min_total=int(sweep_send["recipient_balance_after"]["total_micronoid"]),
            )
        if RESTART_SENDER:
            restart_and_assert_wallet(
                nodes,
                n1,
                "confirmed Sweep25x2 sender state",
                sweep_tx_hashes,
                max_utxo_growth_per_block=True,
            )

        if not SKIP_SPLIT:
            split_amount = choose_split_amount(n1.utxos())
            split_send = send_and_confirm(
                nodes,
                n1,
                n3,
                split_amount,
                "multi-node mixed split send",
                expect_sweep=True,
                expect_split=True,
            )
            if RESTART_SPLIT:
                split_tx_hashes = split_send.get("tx_hashes") or [split_send["tx_hash"]]
                restart_and_assert_wallet(
                    nodes,
                    n3,
                    "confirmed split recipient state",
                    split_tx_hashes,
                    min_total=int(
                        split_send["recipient_balance_after"]["total_micronoid"]
                    ),
                )
                restart_and_assert_wallet(
                    nodes,
                    n1,
                    "confirmed split sender state",
                    split_tx_hashes,
                    max_utxo_growth_per_block=True,
                )

        summary = {
            "final": {
                n.name: {
                    "info": n.info(),
                    "balance": n.balance(),
                    "mempool": n.mempool_size(),
                }
                for n in nodes
            },
            "skip_split": SKIP_SPLIT,
            "restart_recipient": RESTART_RECIPIENT,
            "restart_sender": RESTART_SENDER,
            "restart_split": RESTART_SPLIT,
        }
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2))
        print(f"[summary] wrote {BASE / 'summary.json'}", flush=True)
        print("MULTI-NODE SWEEP LIVE TESTS PASSED", flush=True)
    except Exception:
        print("\n=== MULTI-NODE SWEEP LIVE TEST FAILURE ===", flush=True)
        for n in started:
            print(
                f"\n--- tail {n.name} {n.log_path} ---\n{tail(n.log_path)}", flush=True
            )
        raise
    finally:
        cleanup(started)


if __name__ == "__main__":
    main()
