#!/usr/bin/env python3
# pyright: reportMissingParameterType=false, reportUnknownParameterType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportAny=false
"""Live single-node Sweep25x2 wallet/miner/block scenario.

Covers the roadmap N9 local lifecycle:
- miner creates enough fragmented wallet UTXOs;
- walletSend chooses Sweep25x2 for a payment requiring 5 inputs;
- tx enters mempool with a cached LogicProof and confirms in a mined block;
- mempool drains and wallet pending locks clear;
- optionally, a larger fragmented payment auto-splits into multiple chunks, including Sweep25x2.

Environment knobs:
  NOID_LIVE_SWEEP_START_BLOCKS default 20, raised to at least 30 when split is enabled
  NOID_LIVE_SWEEP_BASE_PORT          default 19800
  NOID_LIVE_SWEEP_SKIP_SPLIT         default 1 (set 0 to run the heavier >25-input split scenario)
  NOID_LIVE_SWEEP_SKIP_CONSOLIDATE   default 0 (only runs in the quick/no-split path)
  NOID_LIVE_SWEEP_RESTART            default 0 (restart node after confirmed sweep/split/consolidation)
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
BASE = ROOT / "target" / "live-tests" / "sweep-shape"
LOGS = BASE / "logs"

START_BLOCKS = int(os.environ.get("NOID_LIVE_SWEEP_START_BLOCKS", "20"))
BASE_PORT = int(os.environ.get("NOID_LIVE_SWEEP_BASE_PORT", "19800"))
SKIP_SPLIT = os.environ.get("NOID_LIVE_SWEEP_SKIP_SPLIT", "1") == "1"
if not SKIP_SPLIT:
    START_BLOCKS = max(START_BLOCKS, 30)
SKIP_CONSOLIDATE = os.environ.get("NOID_LIVE_SWEEP_SKIP_CONSOLIDATE", "0") == "1"
RESTART_AFTER_CONFIRMED = os.environ.get("NOID_LIVE_SWEEP_RESTART", "0") == "1"


class LiveTestError(Exception):
    pass


class Node:
    def __init__(
        self, name, p2p_port, rpc_port, mode="miner", genesis=False, log="info"
    ):
        self.name = name
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.mode = mode
        self.genesis = genesis
        self.log = log
        self.data_dir = BASE / name
        self.log_path = LOGS / f"{name}.log"
        self.proc = None
        self.log_file = None

    @property
    def rpc_url(self):
        return f"http://127.0.0.1:{self.rpc_port}"

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
        self.log_file = open(self.log_path, "ab", buffering=0)
        self.log_file.write(
            f"\n\n===== START {self.name} {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n".encode()
        )
        self.proc = subprocess.Popen(
            args, cwd=ROOT, stdout=self.log_file, stderr=subprocess.STDOUT
        )
        print(
            f"[start] {self.name}: pid={self.proc.pid} rpc={self.rpc_url}", flush=True
        )
        wait_until(
            f"{self.name} RPC ready",
            lambda: rpc(self.rpc_url, "getChainInfo", timeout=2),
            timeout=60,
            interval=0.5,
        )

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return
        print(f"[stop] {self.name}", flush=True)
        try:
            rpc(self.rpc_url, "stop", timeout=3)
        except Exception as e:
            print(f"[stop] rpc stop failed: {e}", flush=True)
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

    def height(self):
        return int(rpc(self.rpc_url, "getChainInfo")["height"])

    def balance(self):
        return rpc(self.rpc_url, "walletGetBalance", timeout=20)

    def utxos(self):
        return rpc(self.rpc_url, "walletListUtxos", timeout=20)

    def mempool_size(self):
        return int(rpc(self.rpc_url, "getMempoolSize", timeout=10))


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


def tail(path, n=160):
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-n:])
    except Exception as e:
        return f"<cannot read {path}: {e}>"


def choose_amount_requiring_inputs(utxos, min_inputs, fee_margin=100_000):
    values = sorted((int(u["value_micronoid"]) for u in utxos), reverse=True)
    if len(values) < min_inputs:
        raise LiveTestError(f"need at least {min_inputs} UTXOs, have {len(values)}")
    amount = sum(values[: min_inputs - 1]) + 1
    available = sum(values[: min(25, len(values))])
    if amount + fee_margin > available:
        raise LiveTestError(
            f"not enough value to force {min_inputs} inputs safely: amount={amount} available25={available}"
        )
    return amount


def choose_split_amount(utxos, fee_margin=500_000):
    values = sorted((int(u["value_micronoid"]) for u in utxos), reverse=True)
    if len(values) <= 25:
        raise LiveTestError(
            f"need more than 25 UTXOs for split scenario, have {len(values)}"
        )
    amount = sum(values[:25]) + 1
    available = sum(values)
    if amount + fee_margin > available:
        raise LiveTestError(
            f"not enough value to force split safely: amount={amount} available={available}"
        )
    return amount


def assert_confirmed(node, tx_hash, label):
    return wait_until(
        f"{label} confirmed {tx_hash[:12]}",
        lambda: rpc(node.rpc_url, "getTx", [tx_hash], timeout=10),
        timeout=600,
        interval=4,
    )


def assert_tx_confirmed(node, tx_hash, label):
    return assert_confirmed(node, tx_hash, label)


def history_hashes(node):
    return {h.get("tx_hash") for h in rpc(node.rpc_url, "walletHistory", timeout=20)}


def restart_and_assert_wallet(
    node, label, tx_hashes, min_total=None, max_utxo_growth_per_block=True
):
    print(f"\n=== Restart after {label} ===", flush=True)
    before_info = (
        node.info()
        if hasattr(node, "info")
        else rpc(node.rpc_url, "getChainInfo", timeout=10)
    )
    before_balance = node.balance()
    before_utxo_count = len(node.utxos())
    before_height = int(before_info["height"])
    before_tip = before_info["best_hash"]

    node.stop()
    node.start()

    wait_until(
        f"{label} restarted node reaches previous tip",
        lambda: (
            info
            if int((info := rpc(node.rpc_url, "getChainInfo", timeout=10))["height"])
            >= before_height
            else False
        ),
        timeout=240,
        interval=3,
    )
    after_info = rpc(node.rpc_url, "getChainInfo", timeout=10)
    after_balance = node.balance()
    after_height = int(after_info["height"])
    after_utxo_count = len(node.utxos())
    expected_min_total = (
        int(before_balance["total_micronoid"]) if min_total is None else min_total
    )

    assert_true(
        int(after_balance["total_micronoid"]) >= expected_min_total,
        f"{label}: balance regressed after restart: before={before_balance} after={after_balance}",
    )
    assert_true(
        int(after_balance["pending_outbound_micronoid"]) == 0,
        f"{label}: pending outbound not clear after restart: {after_balance}",
    )
    seen = history_hashes(node)
    assert_true(
        all(h in seen for h in tx_hashes),
        f"{label}: wallet history missing txs after restart {tx_hashes}: {seen}",
    )
    if max_utxo_growth_per_block:
        allowed = before_utxo_count + max(0, after_height - before_height)
        assert_true(
            after_utxo_count <= allowed,
            f"{label}: UTXOs grew too much after restart; before_count={before_utxo_count} after_count={after_utxo_count} before_tip={before_tip} after_info={after_info}",
        )
    print(
        f"[restart ok] {label}: balance={after_balance} utxos={before_utxo_count}->{after_utxo_count} tip={after_info}",
        flush=True,
    )


def submit_and_confirm(node, to_addr, amount, label):
    print(f"\n=== {label}: walletSend amount={amount} μNOID ===", flush=True)
    before = node.balance()
    result = rpc(node.rpc_url, "walletSend", [to_addr, amount, 0], timeout=300)
    print(f"[send] {json.dumps(result, indent=2)}", flush=True)

    tx_hashes = result.get("tx_hashes") or [result.get("tx_hash")]
    tx_hashes = [h for h in tx_hashes if h]
    tx_shapes = result.get("tx_shapes") or []
    assert_true(tx_hashes, f"{label}: walletSend returned no tx hashes: {result}")
    assert_true(
        len(tx_shapes) == len(tx_hashes),
        f"{label}: tx_shapes not aligned with tx_hashes: {result}",
    )
    assert_true(
        "Sweep25x2" in tx_shapes,
        f"{label}: expected at least one Sweep25x2 chunk, got {tx_shapes}",
    )

    wait_until(
        f"{label} visible in mempool",
        lambda: node.mempool_size() >= len(tx_hashes),
        timeout=180,
        interval=2,
    )
    entries = [rpc(node.rpc_url, "getMempoolEntry", [h], timeout=10) for h in tx_hashes]
    assert_true(
        all(e and e.get("has_proof") for e in entries),
        f"{label}: missing mempool proofs {entries}",
    )
    print(f"[mempool] {json.dumps(entries, indent=2)}", flush=True)

    mid = node.balance()
    assert_true(
        int(mid["pending_outbound_micronoid"]) > 0,
        f"{label}: pending locks did not appear; before={before} mid={mid}",
    )

    for i, h in enumerate(tx_hashes):
        assert_confirmed(node, h, f"{label} chunk {i + 1}/{len(tx_hashes)}")

    wait_until(
        f"{label} mempool drains",
        lambda: node.mempool_size() == 0,
        timeout=240,
        interval=3,
    )
    rpc(node.rpc_url, "walletScan", timeout=240)
    after = node.balance()
    assert_true(
        int(after["pending_outbound_micronoid"]) == 0,
        f"{label}: pending locks did not clear after confirmation: {after}",
    )
    history = rpc(node.rpc_url, "walletHistory", timeout=20)
    seen = {h.get("tx_hash") for h in history}
    assert_true(
        all(h in seen for h in tx_hashes),
        f"{label}: history missing txs {tx_hashes}: {history}",
    )
    return result


def main():
    if not NODE_BIN.exists():
        raise LiveTestError(
            "release binary missing; run cargo build --release -p noid_node --bin paranoid"
        )
    if BASE.exists():
        shutil.rmtree(BASE)
    LOGS.mkdir(parents=True, exist_ok=True)

    node = Node("sweep-single-miner", BASE_PORT, BASE_PORT + 1, genesis=True)
    started = False
    try:
        print("\n=== Sweep live scenario: start single miner ===", flush=True)
        node.start()
        started = True
        wait_until(
            f"miner creates {START_BLOCKS} fragmented coinbase UTXOs",
            lambda: node.height() if node.height() >= START_BLOCKS else False,
            timeout=max(900, START_BLOCKS * 30),
            interval=3,
        )
        scan = rpc(node.rpc_url, "walletScan", timeout=240)
        print(f"[scan] {scan}", flush=True)
        utxos = node.utxos()
        bal = node.balance()
        assert_true(
            len(utxos) >= 5, f"not enough UTXOs for sweep scenario: {len(utxos)}"
        )
        assert_true(int(bal["spendable_micronoid"]) > 0, f"wallet not funded: {bal}")
        print(f"[wallet] balance={bal} utxos={len(utxos)}", flush=True)

        recv1 = rpc(node.rpc_url, "walletNextAddress", timeout=20)["address"]
        sweep_amount = choose_amount_requiring_inputs(utxos, 5)
        sweep = submit_and_confirm(node, recv1, sweep_amount, "Sweep25x2 single tx")
        assert_true(
            sweep.get("split_count") in (None, 1),
            f"single sweep unexpectedly split: {sweep}",
        )
        assert_true(
            sweep.get("shape") == "Sweep25x2",
            f"primary shape is not Sweep25x2: {sweep}",
        )
        assert_true(
            sweep.get("tx_shapes") == ["Sweep25x2"], f"unexpected sweep shapes: {sweep}"
        )
        if RESTART_AFTER_CONFIRMED:
            restart_and_assert_wallet(
                node,
                "confirmed Sweep25x2 send",
                sweep.get("tx_hashes") or [sweep.get("tx_hash")],
            )

        if SKIP_SPLIT and not SKIP_CONSOLIDATE:
            before_height = node.height()
            before_utxos = node.utxos()
            before_count = len(before_utxos)
            assert_true(
                before_count >= 5,
                f"not enough UTXOs for sweep consolidation: {before_count}",
            )
            print("\n=== Sweep25x2 consolidation ===", flush=True)
            cons = rpc(node.rpc_url, "walletConsolidate", [0], timeout=360)
            print(f"[consolidate] {json.dumps(cons, indent=2)}", flush=True)
            assert_true(
                cons.get("shape") == "Sweep25x2",
                f"consolidation did not use Sweep25x2: {cons}",
            )
            input_counts = cons.get("tx_input_counts") or []
            assert_true(
                input_counts and int(input_counts[0]) > 4,
                f"consolidation did not consume >4 inputs: {cons}",
            )
            tx_hash = cons.get("tx_hash")
            assert_true(tx_hash, f"consolidation returned no tx hash: {cons}")
            assert_tx_confirmed(node, tx_hash, "Sweep25x2 consolidation")
            wait_until(
                "consolidation mempool drains",
                lambda: node.mempool_size() == 0,
                timeout=240,
                interval=3,
            )
            rpc(node.rpc_url, "walletScan", timeout=240)
            after_height = node.height()
            after_count = len(node.utxos())
            # Consolidation itself replaces N inputs with 1 output. Every block
            # mined while waiting can also pay this miner wallet one fresh coinbase
            # UTXO, so allow the observed height delta.
            expected_max = (
                before_count
                - int(input_counts[0])
                + 1
                + max(0, after_height - before_height)
            )
            assert_true(
                after_count <= expected_max,
                f"consolidation did not reduce UTXO count enough: before={before_count} after={after_count} inputs={input_counts[0]}",
            )
            print(
                f"[consolidation ok] utxos {before_count} -> {after_count} inputs={input_counts[0]}",
                flush=True,
            )
            if RESTART_AFTER_CONFIRMED:
                restart_and_assert_wallet(
                    node,
                    "confirmed Sweep25x2 consolidation",
                    [tx_hash],
                )

        if not SKIP_SPLIT:
            utxos = node.utxos()
            recv2 = rpc(node.rpc_url, "walletNextAddress", timeout=20)["address"]
            split_amount = choose_split_amount(utxos)
            split = submit_and_confirm(
                node, recv2, split_amount, "fragmented split send"
            )
            assert_true(
                int(split.get("split_count") or 1) > 1,
                f"large fragmented send did not split: {split}",
            )
            assert_true(
                "Sweep25x2" in split.get("tx_shapes", []),
                f"split send did not include Sweep25x2 chunk: {split}",
            )
            if RESTART_AFTER_CONFIRMED:
                restart_and_assert_wallet(
                    node,
                    "confirmed split send",
                    split.get("tx_hashes") or [split.get("tx_hash")],
                )

        summary = {
            "height": node.height(),
            "balance": node.balance(),
            "utxo_count": len(node.utxos()),
            "skip_split": SKIP_SPLIT,
            "skip_consolidate": SKIP_CONSOLIDATE,
            "restart_after_confirmed": RESTART_AFTER_CONFIRMED,
        }
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2))
        print(f"[summary] wrote {BASE / 'summary.json'}", flush=True)
        print("SWEEP LIVE TESTS PASSED", flush=True)
    except Exception:
        print("\n=== SWEEP LIVE TEST FAILURE ===", flush=True)
        if node.log_path.exists():
            print(f"\n--- tail {node.name} ---")
            print(tail(node.log_path))
        raise
    finally:
        if started:
            node.stop()


if __name__ == "__main__":
    main()
