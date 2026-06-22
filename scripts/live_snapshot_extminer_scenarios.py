#!/usr/bin/env python3
# pyright: reportMissingParameterType=false, reportUnknownParameterType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportMissingTypeArgument=false, reportAny=false, reportUnusedCallResult=false, reportUnusedVariable=false, reportUnannotatedClassAttribute=false
"""
Live production scenario for two protocol-critical paths:

1. Snapshot catch-up through a recent suffix containing a user-tx block.
   The late node must later advance its recursive proof through that exact
   non-coinbase block. If recent block proof/sidecar bytes are not preserved,
   the recursive updater cannot pass that height.

2. External mining API competition.
   A normal internal miner and `noid-extminer` mine on different nodes. The
   externally submitted block must be locally validated, stored, broadcast via
   P2P, and followed by the internal miner/relay nodes.
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
EXTMINER_BIN = ROOT / "target" / "release" / "noid-extminer"
BASE = ROOT / "target" / "live-tests" / "snapshot-extminer"
LOGS = BASE / "logs"
FINALITY_DEPTH = 18
MINING_KEY = "snapshot-extminer-live-key-0001"
MINER_THREADS = int(os.environ.get("NOID_LIVE_MINER_THREADS", "4"))


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
        mining_key=None,
        log="info",
    ):
        self.name = name
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.mode = mode
        self.genesis = genesis
        self.seed = seed or []
        self.mining_threads = mining_threads
        self.mining_key = mining_key
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
        if self.proc and self.proc.poll() is None:
            return
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
        if self.mining_threads is not None:
            args.extend(["--mining-threads", str(self.mining_threads)])
        if self.mining_key is not None:
            args.extend(["--mining-key", self.mining_key])
        for seed in self.seed:
            args.extend(["--seed", seed])

        self.log_file = open(self.log_path, "ab", buffering=0)
        self.log_file.write(
            (
                "\n\n===== START %s %s =====\n"
                % (self.name, time.strftime("%Y-%m-%d %H:%M:%S"))
            ).encode()
        )
        self.proc = subprocess.Popen(
            args, cwd=ROOT, stdout=self.log_file, stderr=subprocess.STDOUT
        )
        print(
            f"[start] {self.name}: pid={self.proc.pid} mode={self.mode} rpc={self.rpc_url} p2p={self.seed_addr} seeds={self.seed}",
            flush=True,
        )
        self.wait_rpc(timeout=60)

    def stop(self, graceful=True, timeout=20):
        if not self.proc or self.proc.poll() is not None:
            return
        print(f"[stop] {self.name}: graceful={graceful}", flush=True)
        if graceful:
            try:
                rpc(self.rpc_url, "stop", [], timeout=3, key=self.mining_key)
            except Exception as e:
                print(f"[stop] {self.name}: rpc stop failed: {e}", flush=True)
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=8)
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def wait_rpc(self, timeout=60):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise LiveTestError(
                    f"{self.name} exited early with code {self.proc.returncode}"
                )
            try:
                rpc(self.rpc_url, "getChainInfo", [], timeout=2, key=self.mining_key)
                return
            except Exception as e:
                last = e
                time.sleep(0.5)
        raise LiveTestError(f"{self.name} RPC not ready: {last}")

    def rpc(self, method, params=None, timeout=8):
        return rpc(
            self.rpc_url, method, params or [], timeout=timeout, key=self.mining_key
        )

    def info(self):
        return self.rpc("getChainInfo", timeout=5)

    def height(self):
        return int(self.info()["height"])

    def hash(self):
        return self.info()["best_hash"]

    def peers(self):
        return int(self.rpc("getPeerCount", timeout=5))

    def mempool_size(self):
        return int(self.rpc("getMempoolSize", timeout=5))

    def wallet_status(self):
        return self.rpc("walletStatus", timeout=10)

    def wallet_scan(self):
        return self.rpc("walletScan", timeout=180)

    def mining_info(self):
        return self.rpc("getMiningInfo", timeout=10)

    def recursive_proof_height(self):
        return self.mining_info().get("recursive_proof_height")

    def get_tx(self, tx_hash):
        return self.rpc("getTx", [tx_hash], timeout=10)


class ExternalMiner:
    def __init__(self, name, node, threads=MINER_THREADS, poll_ms=250, log="info"):
        self.name = name
        self.node = node
        self.threads = threads
        self.poll_ms = poll_ms
        self.log = log
        self.log_path = LOGS / f"{name}.log"
        self.proc = None
        self.log_file = None

    def start(self):
        if self.proc and self.proc.poll() is None:
            return
        LOGS.mkdir(parents=True, exist_ok=True)
        args = [
            str(EXTMINER_BIN),
            "--rpc",
            self.node.rpc_url,
            "--key",
            MINING_KEY,
            "--threads",
            str(self.threads),
            "--poll-ms",
            str(self.poll_ms),
            "--log",
            self.log,
        ]
        self.log_file = open(self.log_path, "ab", buffering=0)
        self.log_file.write(
            (
                "\n\n===== START %s %s =====\n"
                % (self.name, time.strftime("%Y-%m-%d %H:%M:%S"))
            ).encode()
        )
        self.proc = subprocess.Popen(
            args, cwd=ROOT, stdout=self.log_file, stderr=subprocess.STDOUT
        )
        print(
            f"[start] {self.name}: pid={self.proc.pid} rpc={self.node.rpc_url} threads={self.threads}",
            flush=True,
        )

    def stop(self, timeout=10):
        if not self.proc or self.proc.poll() is not None:
            return
        print(f"[stop] {self.name}", flush=True)
        self.proc.terminate()
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        if self.log_file:
            self.log_file.close()
            self.log_file = None


class Started:
    def __init__(self):
        self.nodes = []
        self.extminers = []

    def add_node(self, node):
        self.nodes.append(node)

    def add_extminer(self, extminer):
        self.extminers.append(extminer)

    def cleanup(self):
        for ext in reversed(self.extminers):
            try:
                ext.stop()
            except Exception as e:
                print(f"[cleanup] {ext.name}: {e}", flush=True)
        for node in reversed(self.nodes):
            try:
                node.stop(graceful=True, timeout=8)
            except Exception as e:
                print(f"[cleanup] {node.name}: {e}", flush=True)


def rpc(url, method, params=None, timeout=8, key=None):
    method_full = method if method.startswith("paranoid_") else f"paranoid_{method}"
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method_full, "params": params or []}
    ).encode()
    headers = {"content-type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, data=body, headers=headers)
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


def expect_rpc_error(node, method, params=None, needle=None, timeout=8):
    try:
        node.rpc(method, params or [], timeout=timeout)
    except Exception as e:
        msg = str(e)
        if needle and needle not in msg:
            raise LiveTestError(
                f"{node.name} RPC {method} failed with unexpected error: {msg}"
            )
        print(f"[ok] {node.name} {method} rejected as expected: {msg}", flush=True)
        return msg
    raise LiveTestError(f"{node.name} RPC {method} unexpectedly succeeded")


def all_same_tip(nodes, max_lag=0):
    infos = {n.name: n.info() for n in nodes}
    heights = [int(i["height"]) for i in infos.values()]
    hashes = [i["best_hash"] for i in infos.values()]
    if max(heights) - min(heights) > max_lag:
        return False
    if max_lag == 0 and len(set(hashes)) != 1:
        return False
    return {k: (v["height"], v["best_hash"][:12]) for k, v in infos.items()}


def count_lines(path, needle):
    if not path.exists():
        return 0
    return sum(
        1 for line in path.read_text(errors="replace").splitlines() if needle in line
    )


def log_contains(path, needle):
    return path.exists() and needle in path.read_text(errors="replace")


def grep_logs(patterns):
    out = {}
    for log in sorted(LOGS.glob("*.log")):
        text = log.read_text(errors="replace") if log.exists() else ""
        hits = []
        for line in text.splitlines():
            low = line.lower()
            if any(p in low for p in patterns):
                hits.append(line)
        out[log.name] = hits[-120:]
    return out


def tail(path, n=120):
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-n:])
    except Exception as e:
        return f"<cannot read {path}: {e}>"


def checked_binaries():
    missing = [str(p) for p in [NODE_BIN, EXTMINER_BIN] if not p.exists()]
    if missing:
        raise LiveTestError(
            "release binaries missing: "
            + ", ".join(missing)
            + "\nrun: cargo build --release -p noid_node --bin paranoid -p noid-extminer --bin noid-extminer"
        )


def main():
    checked_binaries()
    if BASE.exists():
        shutil.rmtree(BASE)
    LOGS.mkdir(parents=True, exist_ok=True)

    n1 = Node(
        "node1-internal-miner",
        19900,
        19901,
        mode="miner",
        genesis=True,
        mining_threads=MINER_THREADS,
        log="info",
    )
    n2 = Node(
        "node2-extminer-node",
        19910,
        19911,
        mode="extminer",
        seed=[n1.seed_addr],
        mining_key=MINING_KEY,
        log="info",
    )
    n3 = Node(
        "node3-late-snapshot",
        19920,
        19921,
        mode="relay",
        seed=[n2.seed_addr],
        log="info",
    )
    ext = ExternalMiner("noid-extminer-node2", n2, threads=MINER_THREADS)
    started = Started()

    try:
        print(
            "\n=== Scenario 1: bootstrap internal miner and extminer-mode full node ===",
            flush=True,
        )
        n1.start()
        started.add_node(n1)
        expect_rpc_error(
            n1,
            "getBlockTemplate",
            [""],
            needle="external mining API is disabled",
            timeout=10,
        )
        wait_until(
            "node1 mines beyond finality",
            lambda: n1.height() if n1.height() >= FINALITY_DEPTH + 2 else False,
            timeout=600,
            interval=2,
        )
        wait_until(
            "node1 recursive proof available",
            lambda: (
                n1.recursive_proof_height()
                if n1.recursive_proof_height() is not None
                else False
            ),
            timeout=180,
            interval=3,
        )

        n2.start()
        started.add_node(n2)
        wait_until(
            "node2 has peer",
            lambda: n2.peers() if n2.peers() >= 1 else False,
            timeout=90,
            interval=2,
        )
        wait_until(
            "node2 syncs exactly to node1",
            lambda: all_same_tip([n1, n2], max_lag=0),
            timeout=360,
            interval=3,
        )
        tmpl = n2.rpc("getBlockTemplate", [""], timeout=180)
        assert_true(
            int(tmpl["height"]) >= n1.height(),
            f"extminer node template height unexpected: {tmpl}",
        )
        print(
            f"[ok] extminer API enabled only on node2: template_h={tmpl['height']} txs={tmpl['n_txs']}",
            flush=True,
        )

        print(
            "\n=== Scenario 2: mine a real user-tx block before late snapshot sync ===",
            flush=True,
        )
        print(f"[scan] node1 {n1.wallet_scan()}", flush=True)
        print(f"[scan] node2 {n2.wallet_scan()}", flush=True)
        dst_addr = n2.wallet_status()["address"]
        dst_info = n2.rpc("validateAddress", [dst_addr], timeout=10)
        dst_hex = dst_info.get("hex")
        assert_true(
            dst_info.get("valid") and dst_hex and len(dst_hex) == 64,
            f"node2 wallet address unexpected: {dst_info}",
        )
        send = n1.rpc("walletSend", [dst_hex, 1_000_000, 0], timeout=240)
        tx_hash = send["tx_hash"]
        print(f"[send] tx={tx_hash} fee={send['fee_micronoid']}", flush=True)
        wait_until(
            "tx appears in node1/node2 mempools",
            lambda: (
                {n.name: n.mempool_size() for n in [n1, n2]}
                if all(n.mempool_size() >= 1 for n in [n1, n2])
                else False
            ),
            timeout=120,
            interval=2,
        )
        tx_info = wait_until(
            "tx confirmed by internal miner",
            lambda: n1.get_tx(tx_hash),
            timeout=600,
            interval=4,
        )
        user_block_height = int(tx_info["height"])
        print(f"[ok] user tx confirmed at h={user_block_height}: {tx_info}", flush=True)
        wait_until(
            "node1/node2 exact convergence after user block",
            lambda: all_same_tip([n1, n2], max_lag=0),
            timeout=240,
            interval=3,
        )

        print(
            "\n=== Scenario 3: late node snapshot syncs through that user-tx suffix ===",
            flush=True,
        )
        n3.start()
        started.add_node(n3)
        expect_rpc_error(
            n3,
            "getBlockTemplate",
            [""],
            needle="external mining API is disabled",
            timeout=10,
        )
        wait_until(
            "node3 has peer",
            lambda: n3.peers() if n3.peers() >= 1 else False,
            timeout=90,
            interval=2,
        )
        wait_until(
            "node3 snapshot/catch-up reaches node1/node2 tip",
            lambda: all_same_tip([n1, n2, n3], max_lag=0),
            timeout=420,
            interval=3,
        )
        wait_until(
            "node3 log records snapshot proof verification and apply",
            lambda: (
                "snapshot verified+applied"
                if log_contains(n3.log_path, "snapshot: recursive proof verified")
                and log_contains(n3.log_path, "snapshot: fully applied")
                else False
            ),
            timeout=60,
            interval=1,
        )
        node3_snapshot_tip = n3.height()
        node3_snapshot_proof_h = n3.recursive_proof_height()
        print(
            f"[status] node3 snapshot_tip={node3_snapshot_tip} recursive_proof_height={node3_snapshot_proof_h} user_block_height={user_block_height}",
            flush=True,
        )
        assert_true(
            user_block_height <= node3_snapshot_tip,
            "late snapshot did not include the user-tx block in its suffix/tip window",
        )

        print(
            "\n=== Scenario 4: noid-extminer races while snapshot suffix becomes finalized ===",
            flush=True,
        )
        internal_found0 = count_lines(n1.log_path, "block found")
        rpc_submitted0 = count_lines(n2.log_path, "block submitted via RPC")
        base_height = min(n.height() for n in [n1, n2, n3])
        ext.start()
        started.add_extminer(ext)

        def race_status():
            internal_found = count_lines(n1.log_path, "block found") - internal_found0
            ext_solved = count_lines(ext.log_path, "SOLVED")
            rpc_submitted = (
                count_lines(n2.log_path, "block submitted via RPC") - rpc_submitted0
            )
            heights = {n.name: n.height() for n in [n1, n2, n3]}
            if (
                internal_found >= 1
                and ext_solved >= 1
                and rpc_submitted >= 1
                and min(heights.values()) >= base_height + 2
                and all_same_tip([n1, n2, n3], max_lag=1)
            ):
                return {
                    "internal_block_found": internal_found,
                    "extminer_solved": ext_solved,
                    "rpc_submitted": rpc_submitted,
                    "heights": heights,
                }
            return False

        finality_target = user_block_height + FINALITY_DEPTH + 1
        wait_until(
            f"chain reaches finality target for user block h>={finality_target}",
            lambda: (
                {n.name: n.height() for n in [n1, n2, n3]}
                if min(n.height() for n in [n1, n2, n3]) >= finality_target
                else False
            ),
            timeout=900,
            interval=5,
        )
        wait_until(
            f"late node recursive proof advances through user block h={user_block_height}",
            lambda: (
                n3.recursive_proof_height()
                if (n3.recursive_proof_height() or 0) >= user_block_height
                else False
            ),
            timeout=420,
            interval=3,
        )
        race = wait_until(
            "both internal miner and noid-extminer produce accepted blocks",
            race_status,
            timeout=300,
            interval=5,
        )
        wait_until(
            "network settles exactly after extminer/internal race",
            lambda: all_same_tip([n1, n2, n3], max_lag=0),
            timeout=300,
            interval=3,
        )
        ext.stop()

        final = {
            n.name: {
                "info": n.info(),
                "peers": n.peers(),
                "mempool": n.mempool_size(),
                "mining": n.mining_info(),
            }
            for n in [n1, n2, n3]
        }
        interesting = grep_logs(
            [
                "snapshot verified",
                "recursive proof advanced",
                "non-coinbase block missing proof bytes",
                "block submitted via rpc",
                "broadcast block",
                "applied p2p block",
                "solved",
                "submit failed",
                "stale",
                "orphan",
                "reorg",
                "error",
                "warn",
                "panic",
            ]
        )
        summary = {
            "snapshot_suffix_user_block": {
                "tx_hash": tx_hash,
                "user_block_height": user_block_height,
                "node3_snapshot_tip": node3_snapshot_tip,
                "node3_snapshot_recursive_height": node3_snapshot_proof_h,
                "node3_final_recursive_height": n3.recursive_proof_height(),
            },
            "extminer_race": race,
            "final": final,
            "interesting_logs": interesting,
        }
        summary_path = BASE / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2))
        print(f"[summary] wrote {summary_path}", flush=True)
        print("SNAPSHOT + EXTMINER LIVE TESTS PASSED", flush=True)
    except Exception:
        print("\n=== SNAPSHOT + EXTMINER LIVE TEST FAILURE ===", flush=True)
        for path in sorted(LOGS.glob("*.log")):
            print(f"\n--- tail {path.name} ---\n{tail(path, 140)}", flush=True)
        raise
    finally:
        started.cleanup()


if __name__ == "__main__":
    main()
