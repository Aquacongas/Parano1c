#!/usr/bin/env python3
# pyright: reportMissingParameterType=false, reportUnknownParameterType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportMissingTypeArgument=false, reportAny=false, reportUnusedCallResult=false, reportUnusedVariable=false, reportUnannotatedClassAttribute=false
import json
import re
import shutil
import struct
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE_BIN = ROOT / "target" / "release" / "paranoid"
CLI_BIN = ROOT / "target" / "release" / "noid-cli"
BASE = ROOT / "target" / "live-tests" / "fee-mempool-miner"
LOGS = BASE / "logs"

BLOCK_HEADER_WIRE_SIZE = 276
MIN_FEE_BASE = 5_000
FEE_PER_IO = 500
STATE_GROWTH_FEE_BASE = 2_500
LOG_SLOTS_GENESIS = 24
BASE_REWARD_MICRONOID = 50_000_000
FLOOR_REWARD_MICRONOID = 1_000_000


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
        mining_threads=None,
        log="info",
    ):
        self.name = name
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.mode = mode
        self.genesis = genesis
        self.seed = seed or []
        self.mining_threads = mining_threads
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
        if self.mining_threads is not None:
            args.extend(["--mining-threads", str(self.mining_threads)])
        if self.genesis:
            args.append("--genesis")
        for seed in self.seed:
            args.extend(["--seed", seed])
        self.log_file = open(self.log_path, "ab", buffering=0)
        self.log_file.write(
            (
                f"\n\n===== START {self.name} {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n"
            ).encode()
        )
        self.proc = subprocess.Popen(
            args, cwd=ROOT, stdout=self.log_file, stderr=subprocess.STDOUT
        )
        print(
            f"[start] {self.name}: pid={self.proc.pid} rpc={self.rpc_url} p2p={self.seed_addr}",
            flush=True,
        )
        wait_until(
            f"{self.name} RPC ready",
            lambda: rpc(self.rpc_url, "getChainInfo"),
            timeout=45,
            interval=0.5,
        )

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return
        print(f"[stop] {self.name}", flush=True)
        try:
            rpc(self.rpc_url, "stop", timeout=3)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def height(self):
        return int(rpc(self.rpc_url, "getChainInfo")["height"])

    def info(self):
        return rpc(self.rpc_url, "getChainInfo")

    def mempool_size(self):
        return int(rpc(self.rpc_url, "getMempoolSize"))


def rpc(url, method, params=None, timeout=8):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": f"paranoid_{method}",
            "params": params or [],
        }
    ).encode()
    req = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    if "error" in payload:
        raise LiveTestError(f"RPC {method} error: {payload['error']}")
    return payload.get("result")


def cli(node, args, json_mode=False, timeout=120, check=True):
    cmd = [str(CLI_BIN), "--rpc", node.rpc_url]
    if json_mode:
        cmd.append("--json")
    cmd.extend(args)
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    print(f"[cli] {node.name}$ {' '.join(args)} -> {proc.returncode}", flush=True)
    if check and proc.returncode != 0:
        raise LiveTestError(
            f"CLI failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc.stdout.strip(), proc.stderr.strip(), proc.returncode


def cli_json(node, args, timeout=120):
    out, err, _ = cli(node, args, json_mode=True, timeout=timeout)
    if not out:
        raise LiveTestError(
            f"CLI JSON command produced no stdout: {args}; stderr={err}"
        )
    return json.loads(out)


def assert_true(cond, msg):
    if not cond:
        raise LiveTestError(msg)


def assert_eq(actual, expected, msg):
    if actual != expected:
        raise LiveTestError(f"{msg}: expected {expected!r}, got {actual!r}")


def assert_contains(text, needle, label):
    if needle not in text:
        raise LiveTestError(f"{label}: expected {needle!r} in output:\n{text}")


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


def same_tip(nodes):
    infos = {n.name: n.info() for n in nodes}
    hashes = {i["best_hash"] for i in infos.values()}
    heights = {int(i["height"]) for i in infos.values()}
    if len(hashes) == 1 and len(heights) == 1:
        return {k: (v["height"], v["best_hash"][:12]) for k, v in infos.items()}
    return False


def extract_tx_hash(send_output):
    m = re.search(r"[0-9a-f]{64}", send_output)
    if not m:
        raise LiveTestError(
            f"could not extract tx hash from send output:\n{send_output}"
        )
    return m.group(0)


def pressure_multiplier(active_slot_count, log_slots):
    capacity = max(1, 1 << log_slots)
    bps = active_slot_count * 10_000 // capacity
    if bps >= 9_000:
        return 8
    if bps >= 7_500:
        return 4
    if bps >= 5_000:
        return 2
    return 1


def fee_breakdown(n_inputs, n_outputs, active_slot_count, log_slots):
    net_new = max(0, n_outputs - n_inputs)
    io = FEE_PER_IO * (n_inputs + n_outputs)
    growth = (
        STATE_GROWTH_FEE_BASE
        * pressure_multiplier(active_slot_count, log_slots)
        * net_new
    )
    total = MIN_FEE_BASE + io + growth
    return {
        "base": MIN_FEE_BASE,
        "io": io,
        "state_growth": growth,
        "required_total": total,
        "burned": growth,
    }


def expected_fee_estimate(n_outputs, info):
    return fee_breakdown(
        1, n_outputs, int(info["active_slot_count"]), int(info["log_slots"])
    )["required_total"]


def block_reward(log_slots):
    expansions = max(0, log_slots - LOG_SLOTS_GENESIS)
    reward = BASE_REWARD_MICRONOID >> expansions if expansions < 64 else 0
    return max(reward, FLOOR_REWARD_MICRONOID)


def take(buf, off, n):
    if off + n > len(buf):
        raise LiveTestError("truncated block wire")
    return buf[off : off + n], off + n


def take_u32(buf, off):
    raw, off = take(buf, off, 4)
    return struct.unpack("<I", raw)[0], off


def take_u64(buf, off):
    raw, off = take(buf, off, 8)
    return struct.unpack("<Q", raw)[0], off


def take_u128(buf, off):
    raw, off = take(buf, off, 16)
    return int.from_bytes(raw, "little"), off


def take_bool(buf, off):
    raw, off = take(buf, off, 1)
    if raw[0] not in (0, 1):
        raise LiveTestError(f"invalid bool byte {raw[0]}")
    return raw[0] == 1, off


def decode_block(block_hex):
    buf = bytes.fromhex(block_hex)
    off = BLOCK_HEADER_WIRE_SIZE
    n_txs, off = take_u32(buf, off)
    txs = []
    for _ in range(n_txs):
        _, off = take(buf, off, 32)  # epoch_anchor
        fee, off = take_u128(buf, off)
        n_inputs, off = take_u32(buf, off)
        inputs = []
        for _ in range(n_inputs):
            slot, off = take_u32(buf, off)
            value, off = take_u64(buf, off)
            _, off = take(buf, off, 32)  # owner
            _, off = take(buf, off, 32)  # spend_secret
            _, off = take(buf, off, 32)  # auth_tag
            valid, off = take_bool(buf, off)
            inputs.append({"slot": slot, "value": value, "valid": valid})
        n_outputs, off = take_u32(buf, off)
        outputs = []
        for _ in range(n_outputs):
            slot, off = take_u32(buf, off)
            value, off = take_u64(buf, off)
            owner, off = take(buf, off, 32)
            valid, off = take_bool(buf, off)
            outputs.append(
                {"slot": slot, "value": value, "owner": owner.hex(), "valid": valid}
            )
        is_coinbase, off = take_bool(buf, off)
        tx_hash, off = take(buf, off, 32)
        txs.append(
            {
                "fee": fee,
                "n_inputs": sum(1 for i in inputs if i["valid"]),
                "n_outputs": sum(1 for o in outputs if o["valid"]),
                "outputs": [o for o in outputs if o["valid"]],
                "is_coinbase": is_coinbase,
                "tx_hash": tx_hash.hex(),
            }
        )
    if off != len(buf):
        raise LiveTestError(f"block wire trailing bytes: {len(buf) - off}")
    return txs


def verify_miner_payout(node, tx_hash):
    tx_info = rpc(node.rpc_url, "getTx", [tx_hash], timeout=10)
    assert_true(tx_info is not None, f"tx {tx_hash} not confirmed")
    height = int(tx_info["height"])
    header = rpc(node.rpc_url, "getBlockHeader", [height], timeout=10)
    parent = rpc(node.rpc_url, "getBlockHeader", [height - 1], timeout=10)
    block_hex = rpc(node.rpc_url, "getBlock", [height], timeout=10)
    assert_true(block_hex is not None, f"recent block {height} unavailable")
    txs = decode_block(block_hex)
    assert_true(
        txs and txs[0]["is_coinbase"], f"block {height} has no first coinbase: {txs}"
    )
    coinbase_value = sum(o["value"] for o in txs[0]["outputs"])
    claimable_fees = 0
    burned = 0
    for tx in txs[1:]:
        bd = fee_breakdown(
            tx["n_inputs"],
            tx["n_outputs"],
            int(parent["active_slot_count"]),
            int(parent["log_slots"]),
        )
        assert_true(
            tx["fee"] >= bd["required_total"],
            f"confirmed tx below required fee: tx={tx} breakdown={bd}",
        )
        burned += bd["burned"]
        claimable_fees += max(0, tx["fee"] - bd["burned"])
    expected_coinbase = block_reward(int(header["log_slots"])) + claimable_fees
    assert_eq(
        coinbase_value, expected_coinbase, f"miner payout mismatch at block {height}"
    )
    print(
        f"[ok] block {height} miner payout: coinbase={coinbase_value} reward={block_reward(int(header['log_slots']))} claimable_fees={claimable_fees} burned={burned}",
        flush=True,
    )
    return {
        "height": height,
        "coinbase": coinbase_value,
        "claimable_fees": claimable_fees,
        "burned": burned,
    }


def cleanup(nodes):
    for n in reversed(nodes):
        try:
            n.stop()
        except Exception as e:
            print(f"[cleanup] {n.name}: {e}", flush=True)


def main():
    if not NODE_BIN.exists() or not CLI_BIN.exists():
        raise LiveTestError(
            "release binaries missing; run cargo build --release -p noid_node --bin paranoid --bin noid-cli"
        )
    if BASE.exists():
        shutil.rmtree(BASE)
    LOGS.mkdir(parents=True, exist_ok=True)

    miner = Node("fee-node1-miner", 19600, 19601, mode="miner", genesis=True)
    relay = Node(
        "fee-node2-relay-wallet", 19610, 19611, mode="relay", seed=[miner.seed_addr]
    )
    nodes = [miner, relay]
    started = []
    tx_hashes = []
    payouts = []

    try:
        print(
            "\n=== Fee Scenario 1: start miner and relay, sync wallets ===", flush=True
        )
        miner.start()
        started.append(miner)
        wait_until(
            "miner height >= 20",
            lambda: miner.height() if miner.height() >= 20 else False,
            timeout=480,
            interval=2,
        )
        relay.start()
        started.append(relay)
        wait_until("relay syncs", lambda: same_tip(nodes), timeout=240, interval=3)
        rpc(miner.rpc_url, "walletScan", timeout=180)
        rpc(relay.rpc_url, "walletScan", timeout=180)

        print(
            "\n=== Fee Scenario 2: estimateFee and CLI output match formula ===",
            flush=True,
        )
        info = miner.info()
        for n_outputs in [0, 1, 2, 3, 8]:
            expected = expected_fee_estimate(n_outputs, info)
            got_rpc = int(rpc(miner.rpc_url, "estimateFee", [n_outputs], timeout=10))
            got_cli = int(cli_json(miner, ["estimate-fee", str(n_outputs)]))
            assert_eq(got_rpc, expected, f"RPC estimateFee({n_outputs})")
            assert_eq(got_cli, expected, f"CLI JSON estimate-fee {n_outputs}")
        out, _, _ = cli(miner, ["estimate-fee", "3"])
        assert_contains(out, "Formula:", "estimate-fee human output")
        assert_true(
            "v2" not in out.lower(),
            f"estimate-fee output should not mention v2:\n{out}",
        )

        print(
            "\n=== Fee Scenario 3: underpriced explicit send is rejected and mempools stay clean ===",
            flush=True,
        )
        dst_hex = rpc(
            relay.rpc_url,
            "validateAddress",
            [rpc(relay.rpc_url, "walletStatus")["address"]],
            timeout=10,
        )["hex"]
        low_out, low_err, low_code = cli(
            miner,
            ["send", dst_hex, "0.100000", "--fee", "0.000001"],
            timeout=300,
            check=False,
        )
        assert_true(
            low_code != 0,
            f"underpriced send unexpectedly succeeded:\nstdout={low_out}\nstderr={low_err}",
        )
        assert_true(
            "BelowMinFee" in low_err or "BelowMinFee" in low_out,
            f"underpriced failure did not mention BelowMinFee:\nstdout={low_out}\nstderr={low_err}",
        )
        wait_until(
            "mempools empty after rejected tx",
            lambda: all(n.mempool_size() == 0 for n in nodes),
            timeout=60,
            interval=2,
        )

        print(
            "\n=== Fee Scenario 4: auto send fee, mempool list/entry, confirmation, miner payout ===",
            flush=True,
        )
        expected_send_fee = int(rpc(miner.rpc_url, "estimateFee", [2], timeout=10))
        send_out, _, _ = cli(miner, ["send", dst_hex, "1.000000"], timeout=300)
        tx1 = extract_tx_hash(send_out)
        tx_hashes.append(tx1)
        assert_contains(send_out, "(auto)", "send auto fee output")
        send_fee_match = re.search(r"\((\d+) μNOID\).*\(auto\)", send_out)
        if send_fee_match is None:
            raise LiveTestError(
                f"could not parse auto fee from send output:\n{send_out}"
            )
        actual_send_fee = int(send_fee_match.group(1))
        assert_eq(actual_send_fee, expected_send_fee, "wallet auto send fee")
        wait_until(
            "tx1 visible in both mempools",
            lambda: all(n.mempool_size() >= 1 for n in nodes),
            timeout=120,
            interval=1,
        )
        for n in nodes:
            mp = cli_json(n, ["mempool"])
            assert_true(mp["size"] >= 1, f"{n.name} mempool JSON missing tx: {mp}")
            entries = {e["tx_hash"]: e for e in mp["txs"]}
            assert_true(tx1 in entries, f"{n.name} mempool list missing {tx1}: {mp}")
            entry = cli_json(n, ["mempool-tx", tx1])
            assert_eq(
                entry["fee_micronoid"], actual_send_fee, f"{n.name} mempool-tx fee"
            )
            assert_eq(
                entry["fee_rate"],
                entries[tx1]["fee_rate"],
                f"{n.name} mempool list/entry fee_rate",
            )
            assert_eq(entry["n_inputs"], 1, f"{n.name} send n_inputs")
            assert_eq(entry["n_outputs"], 2, f"{n.name} send n_outputs")
            bd = fee_breakdown(
                entry["n_inputs"],
                entry["n_outputs"],
                int(info["active_slot_count"]),
                int(info["log_slots"]),
            )
            assert_eq(
                entry["fee_micronoid"],
                bd["required_total"],
                f"{n.name} send required fee",
            )
        out, _, _ = cli(relay, ["mempool"])
        assert_contains(out, "Pending", "mempool human output")
        assert_contains(out, "fee (μNOID)", "mempool human output")
        wait_until(
            "tx1 confirmed",
            lambda: rpc(miner.rpc_url, "getTx", [tx1], timeout=10),
            timeout=480,
            interval=3,
        )
        payouts.append(verify_miner_payout(miner, tx1))
        wait_until(
            "mempools drain after tx1",
            lambda: all(n.mempool_size() == 0 for n in nodes),
            timeout=180,
            interval=3,
        )
        out, _, _ = cli(relay, ["mempool-tx", tx1])
        assert_contains(out, "not in the mempool", "mempool-tx after confirmation")

        print(
            "\n=== Fee Scenario 5: second auto send creates multiple recipient UTXOs ===",
            flush=True,
        )
        send2 = rpc(miner.rpc_url, "walletSend", [dst_hex, 2_000_000, 0], timeout=240)
        tx2 = send2["tx_hash"]
        tx_hashes.append(tx2)
        assert_eq(
            int(send2["fee_micronoid"]),
            int(rpc(miner.rpc_url, "estimateFee", [2], timeout=10)),
            "RPC walletSend auto fee",
        )
        wait_until(
            "tx2 visible in relay mempool",
            lambda: relay.mempool_size() >= 1,
            timeout=120,
            interval=1,
        )
        entry2 = rpc(relay.rpc_url, "getMempoolEntry", [tx2], timeout=10)
        assert_true(
            entry2 is not None and entry2["has_proof"],
            f"tx2 not proved in relay mempool: {entry2}",
        )
        wait_until(
            "tx2 confirmed",
            lambda: rpc(miner.rpc_url, "getTx", [tx2], timeout=10),
            timeout=480,
            interval=3,
        )
        payouts.append(verify_miner_payout(miner, tx2))
        wait_until(
            "mempools drain after tx2",
            lambda: all(n.mempool_size() == 0 for n in nodes),
            timeout=180,
            interval=3,
        )

        print(
            "\n=== Fee Scenario 6: recipient consolidate auto-fee is safe and miner payout is correct ===",
            flush=True,
        )
        scan = rpc(relay.rpc_url, "walletScan", timeout=180)
        assert_true(
            scan["found_utxos"] >= 2,
            f"recipient needs at least 2 UTXOs to consolidate: {scan}",
        )
        protocol_consolidate_min = fee_breakdown(
            4, 1, int(relay.info()["active_slot_count"]), int(relay.info()["log_slots"])
        )["required_total"]
        relay_fee_floor = int(
            rpc(relay.rpc_url, "getMempoolInfo", timeout=10)["fee_floor"]
        )
        expected_consolidate_auto = max(protocol_consolidate_min, relay_fee_floor)
        consolidate = rpc(relay.rpc_url, "walletConsolidate", [0], timeout=240)
        tx3 = consolidate["tx_hash"]
        tx_hashes.append(tx3)
        assert_eq(
            int(consolidate["fee_micronoid"]),
            expected_consolidate_auto,
            "walletConsolidate auto fee",
        )
        wait_until(
            "consolidate tx visible",
            lambda: all(n.mempool_size() >= 1 for n in nodes),
            timeout=120,
            interval=1,
        )
        c_entry = rpc(miner.rpc_url, "getMempoolEntry", [tx3], timeout=10)
        assert_true(c_entry is not None, "consolidate mempool entry missing")
        assert_eq(c_entry["n_outputs"], 1, "consolidate n_outputs")
        assert_true(
            c_entry["n_inputs"] >= 2,
            f"consolidate should spend multiple inputs: {c_entry}",
        )
        required_actual_shape = fee_breakdown(
            c_entry["n_inputs"],
            c_entry["n_outputs"],
            int(relay.info()["active_slot_count"]),
            int(relay.info()["log_slots"]),
        )["required_total"]
        assert_true(
            c_entry["fee_micronoid"] >= required_actual_shape,
            f"consolidate auto fee not safe: entry={c_entry} required={required_actual_shape}",
        )
        wait_until(
            "consolidate confirmed",
            lambda: rpc(miner.rpc_url, "getTx", [tx3], timeout=10),
            timeout=480,
            interval=3,
        )
        payouts.append(verify_miner_payout(miner, tx3))
        wait_until(
            "final mempools empty",
            lambda: all(n.mempool_size() == 0 for n in nodes),
            timeout=180,
            interval=3,
        )

        print("\n=== Final fee/mempool/miner status ===", flush=True)
        wait_until(
            "final convergence", lambda: same_tip(nodes), timeout=180, interval=3
        )
        summary = {
            "final": {
                n.name: {
                    "info": n.info(),
                    "mempool": n.mempool_size(),
                    "wallet": rpc(n.rpc_url, "walletStatus", timeout=10),
                }
                for n in nodes
            },
            "tx_hashes": tx_hashes,
            "miner_payouts": payouts,
        }
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2))
        print(f"[summary] wrote {BASE / 'summary.json'}", flush=True)
        print("FEE/MEMPOOL/MINER LIVE TESTS PASSED", flush=True)
    except Exception:
        print("\n=== FEE/MEMPOOL/MINER LIVE TEST FAILURE ===", flush=True)
        for n in started:
            if n.log_path.exists():
                print(f"\n--- tail {n.name} ---")
                print(
                    "\n".join(
                        n.log_path.read_text(errors="replace").splitlines()[-140:]
                    )
                )
        raise
    finally:
        cleanup(started)


if __name__ == "__main__":
    main()
