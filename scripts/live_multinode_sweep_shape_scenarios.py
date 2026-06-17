#!/usr/bin/env python3
# pyright: reportMissingParameterType=false, reportUnknownParameterType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportAny=false
"""Live multi-node Sweep25x2 / mixed-shape propagation scenario.

Covers:
- 3-node sync with one miner and two relays started before funding blocks;
- Sweep25x2 walletSend enters mempools, gossips, confirms, and converges;
- optionally, fragmented split send submits mixed chunks (Sweep25x2 + Standard4x8) and confirms;
- recipient wallet balance increases by the sent amount without explicit post-confirmation rescan.

Environment knobs:
  NOID_LIVE_MULTI_SWEEP_START_BLOCKS default 20 (18+ required for recursive aggregation proof readiness)
  NOID_LIVE_MULTI_SWEEP_BASE_PORT    default 19900
  NOID_LIVE_MULTI_SWEEP_SKIP_SPLIT   default 1 (set 0 to run the heavier >25-input split scenario)
  NOID_LIVE_MULTI_SWEEP_LATE_JOIN    default 0 (start relays after funding blocks)
  NOID_LIVE_MULTI_SWEEP_RESTART      default 0 (restart first recipient after Sweep25x2)
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
LATE_JOIN = os.environ.get("NOID_LIVE_MULTI_SWEEP_LATE_JOIN", "0") == "1"
RESTART_RECIPIENT = os.environ.get("NOID_LIVE_MULTI_SWEEP_RESTART", "0") == "1"


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
        if LATE_JOIN:
            print(
                "\n=== Multi-node sweep: late-join relays after funding blocks ===",
                flush=True,
            )
            n1.start()
            started.append(n1)
            wait_until(
                f"node1 mines {START_BLOCKS} funding blocks",
                lambda: n1.height() if n1.height() >= START_BLOCKS else False,
                timeout=max(900, START_BLOCKS * 35),
                interval=3,
            )
            wait_until(
                "node1 has recursive proof for snapshot sync",
                lambda: rpc(n1.rpc_url, "getRecursiveProof", timeout=20) is not None,
                timeout=240,
                interval=5,
            )
            n2.start()
            started.append(n2)
            n3.start()
            started.append(n3)
        else:
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
        if not LATE_JOIN:
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

        if RESTART_RECIPIENT:
            print("\n=== Restart recipient after confirmed Sweep25x2 ===", flush=True)
            expected_balance = int(
                sweep_send["recipient_balance_after"]["total_micronoid"]
            )
            expected_tip = n1.info()["best_hash"]
            n2.stop()
            n2.start()
            wait_until(
                "restarted recipient has peers",
                lambda: n2.peers() if n2.peers() >= 1 else False,
                timeout=120,
                interval=2,
            )
            wait_until(
                "restarted recipient reconverges",
                lambda: same_tip(nodes, max_lag=0),
                timeout=240,
                interval=4,
            )
            post_restart_balance = n2.balance()
            assert_true(
                int(post_restart_balance["total_micronoid"]) >= expected_balance,
                f"recipient balance not persisted after restart: expected>={expected_balance} got={post_restart_balance}",
            )
            assert_true(
                n2.info()["best_hash"] == expected_tip or same_tip(nodes, max_lag=0),
                f"recipient did not persist/reconverge to expected tip {expected_tip}: {n2.info()}",
            )
            print(
                f"[restart ok] {n2.name}: balance={post_restart_balance} tip={n2.info()}",
                flush=True,
            )

        if not SKIP_SPLIT:
            split_amount = choose_split_amount(n1.utxos())
            send_and_confirm(
                nodes,
                n1,
                n3,
                split_amount,
                "multi-node mixed split send",
                expect_sweep=True,
                expect_split=True,
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
            "late_join": LATE_JOIN,
            "restart_recipient": RESTART_RECIPIENT,
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
