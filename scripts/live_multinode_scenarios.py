#!/usr/bin/env python3
# pyright: reportMissingParameterType=false, reportUnknownParameterType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportMissingTypeArgument=false, reportAny=false, reportUnusedCallResult=false, reportUnusedVariable=false, reportUnannotatedClassAttribute=false
import json
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target" / "release" / "paranoid"
BASE = ROOT / "target" / "live-tests" / "multinode"
LOGS = BASE / "logs"
FINALITY_DEPTH = 18


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
        if self.proc and self.proc.poll() is None:
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        LOGS.mkdir(parents=True, exist_ok=True)
        args = [
            str(BIN),
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
                "\n\n===== START %s %s =====\n"
                % (self.name, time.strftime("%Y-%m-%d %H:%M:%S"))
            ).encode()
        )
        self.proc = subprocess.Popen(
            args, cwd=ROOT, stdout=self.log_file, stderr=subprocess.STDOUT
        )
        print(
            f"[start] {self.name}: pid={self.proc.pid} rpc={self.rpc_url} p2p={self.seed_addr} mode={self.mode} genesis={self.genesis} seeds={self.seed}",
            flush=True,
        )
        self.wait_rpc(timeout=45)

    def stop(self, graceful=True, timeout=20):
        if not self.proc or self.proc.poll() is not None:
            return
        print(f"[stop] {self.name}: graceful={graceful}", flush=True)
        if graceful:
            try:
                rpc(self.rpc_url, "stop", [], timeout=3)
            except Exception as e:
                print(f"[stop] {self.name}: rpc stop failed: {e}", flush=True)
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"[stop] {self.name}: terminate", flush=True)
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                print(f"[stop] {self.name}: kill", flush=True)
                self.proc.kill()
                self.proc.wait(timeout=8)
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def crash(self):
        if not self.proc or self.proc.poll() is not None:
            return
        print(f"[crash] {self.name}: SIGTERM", flush=True)
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=8)
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def wait_rpc(self, timeout=45):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise LiveTestError(
                    f"{self.name} exited early with code {self.proc.returncode}"
                )
            try:
                rpc(self.rpc_url, "getChainInfo", [], timeout=2)
                return
            except Exception as e:
                last = e
                time.sleep(0.5)
        raise LiveTestError(f"{self.name} RPC not ready: {last}")

    def info(self):
        return rpc(self.rpc_url, "getChainInfo", [], timeout=5)

    def height(self):
        return int(self.info()["height"])

    def hash(self):
        return self.info()["best_hash"]

    def peers(self):
        return int(rpc(self.rpc_url, "getPeerCount", [], timeout=5))

    def mempool_size(self):
        return int(rpc(self.rpc_url, "getMempoolSize", [], timeout=5))

    def wallet_status(self):
        return rpc(self.rpc_url, "walletStatus", [], timeout=10)

    def wallet_scan(self):
        return rpc(self.rpc_url, "walletScan", [], timeout=120)

    def recursive_proof(self):
        return rpc(self.rpc_url, "getRecursiveProof", [], timeout=10)

    def mining_info(self):
        return rpc(self.rpc_url, "getMiningInfo", [], timeout=10)

    def recursive_proof_height(self):
        return self.mining_info().get("recursive_proof_height")


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


def all_same_tip(nodes, max_lag=0):
    infos = {n.name: n.info() for n in nodes}
    heights = [int(i["height"]) for i in infos.values()]
    hashes = [i["best_hash"] for i in infos.values()]
    if max(heights) - min(heights) > max_lag:
        return False
    if max_lag == 0 and len(set(hashes)) != 1:
        return False
    return {k: (v["height"], v["best_hash"][:12]) for k, v in infos.items()}


def tail(path, n=80):
    try:
        lines = path.read_text(errors="replace").splitlines()
        return "\n".join(lines[-n:])
    except Exception as e:
        return f"<cannot read {path}: {e}>"


def grep_logs(patterns):
    out = {}
    for log in sorted(LOGS.glob("*.log")):
        text = log.read_text(errors="replace") if log.exists() else ""
        hits = []
        for line in text.splitlines():
            low = line.lower()
            if any(p in low for p in patterns):
                hits.append(line)
        out[log.name] = hits[-80:]
    return out


def cleanup(nodes):
    for n in reversed(nodes):
        try:
            n.stop(graceful=True, timeout=8)
        except Exception as e:
            print(f"[cleanup] {n.name}: {e}", flush=True)


def main():
    if not BIN.exists():
        raise LiveTestError(f"binary missing: {BIN}")
    if BASE.exists():
        shutil.rmtree(BASE)
    LOGS.mkdir(parents=True, exist_ok=True)

    n1 = Node(
        "node1-genesis-miner",
        19400,
        19401,
        mode="miner",
        genesis=True,
        mining_threads=None,
        log="info",
    )
    n2 = Node(
        "node2-relay",
        19410,
        19411,
        mode="relay",
        seed=[n1.seed_addr],
        mining_threads=None,
        log="info",
    )
    n3 = Node(
        "node3-relay-via-node2",
        19420,
        19421,
        mode="relay",
        seed=[n2.seed_addr],
        mining_threads=None,
        log="info",
    )
    n4 = Node(
        "node4-late-miner",
        19430,
        19431,
        mode="miner",
        seed=[n2.seed_addr, n3.seed_addr],
        mining_threads=None,
        log="info",
    )
    started = []

    try:
        print("\n=== Scenario 1: genesis miner produces 18+ blocks ===", flush=True)
        n1.start()
        started.append(n1)
        wait_until(
            "node1 height >= 18",
            lambda: n1.height() if n1.height() >= 18 else False,
            timeout=420,
            interval=2,
        )
        wait_until(
            "node1 recursive proof available",
            lambda: len(n1.recursive_proof() or "") if n1.recursive_proof() else False,
            timeout=180,
            interval=3,
        )
        print(f"[status] node1 {n1.info()} wallet={n1.wallet_status()}", flush=True)

        print("\n=== Scenario 2: node2 relay syncs from node1 ===", flush=True)
        n2.start()
        started.append(n2)
        wait_until(
            "node2 has a peer",
            lambda: n2.peers() if n2.peers() >= 1 else False,
            timeout=90,
            interval=2,
        )
        wait_until(
            "node2 catches node1 tip",
            lambda: all_same_tip([n1, n2], max_lag=2),
            timeout=420,
            interval=3,
        )
        print(f"[status] node2 {n2.info()} peers={n2.peers()}", flush=True)

        print("\n=== Scenario 3: node3 syncs using node2 as only seed ===", flush=True)
        n3.start()
        started.append(n3)
        wait_until(
            "node3 has a peer",
            lambda: n3.peers() if n3.peers() >= 1 else False,
            timeout=90,
            interval=2,
        )
        wait_until(
            "node1/node2/node3 converge",
            lambda: all_same_tip([n1, n2, n3], max_lag=2),
            timeout=420,
            interval=3,
        )
        print(f"[status] node3 {n3.info()} peers={n3.peers()}", flush=True)

        print(
            "\n=== Scenario 4: wallet send node1 -> node3 and mempool gossip convergence ===",
            flush=True,
        )
        # Ensure wallets know current coinbase/snapshot UTXOs.
        print(f"[scan] node1 {n1.wallet_scan()}", flush=True)
        print(f"[scan] node3 {n3.wallet_scan()}", flush=True)
        dst_addr = n3.wallet_status()["address"]
        dst_info = rpc(n3.rpc_url, "validateAddress", [dst_addr], timeout=10)
        dst = dst_info.get("hex")
        assert_true(
            dst_info.get("valid") and dst and len(dst) == 64,
            f"node3 wallet address unexpected: {dst_info}",
        )
        send = rpc(n1.rpc_url, "walletSend", [dst, 1_000_000, 0], timeout=180)
        tx_hash = send["tx_hash"]
        print(f"[send] tx={tx_hash} fee={send['fee_micronoid']}", flush=True)
        wait_until(
            "tx appears in all mempools",
            lambda: (
                {n.name: n.mempool_size() for n in [n1, n2, n3]}
                if all(n.mempool_size() >= 1 for n in [n1, n2, n3])
                else False
            ),
            timeout=120,
            interval=2,
        )
        for n in [n1, n2, n3]:
            entry = rpc(n.rpc_url, "getMempoolEntry", [tx_hash], timeout=10)
            assert_true(
                entry is not None and entry.get("has_proof"),
                f"{n.name} missing proved mempool tx",
            )
        print("[ok] mempool tx is present with proof on all three nodes", flush=True)
        # Let node1 mine the transaction and check confirmation propagates.
        start_h = n1.height()
        wait_until(
            "tx confirmed on node1",
            lambda: rpc(n1.rpc_url, "getTx", [tx_hash], timeout=10),
            timeout=420,
            interval=4,
        )
        wait_until(
            "mempools drain after confirmation",
            lambda: (
                {n.name: n.mempool_size() for n in [n1, n2, n3]}
                if all(n.mempool_size() == 0 for n in [n1, n2, n3])
                else False
            ),
            timeout=180,
            interval=3,
        )
        wait_until(
            "post-tx chain convergence",
            lambda: all_same_tip([n1, n2, n3], max_lag=2),
            timeout=180,
            interval=3,
        )
        print(
            f"[ok] tx confirmed; height advanced from {start_h} to {n1.height()}",
            flush=True,
        )

        print(
            "\n=== Scenario 5: stop node1, start late miner node4 via node2/node3, sync then mine ===",
            flush=True,
        )
        n1.crash()
        time.sleep(8)
        n4.start()
        started.append(n4)
        wait_until(
            "node4 has peer",
            lambda: n4.peers() if n4.peers() >= 1 else False,
            timeout=90,
            interval=2,
        )
        wait_until(
            "node4 syncs to relays",
            lambda: all_same_tip([n2, n3, n4], max_lag=2),
            timeout=420,
            interval=3,
        )
        node4_snapshot_tip = n4.height()
        node4_snapshot_recursive_height = n4.recursive_proof_height()
        assert_true(
            node4_snapshot_recursive_height is not None,
            f"node4 snapshot synced without recursive proof height: {n4.mining_info()}",
        )
        print(
            f"[status] node4 snapshot tip={node4_snapshot_tip} recursive_proof_height={node4_snapshot_recursive_height}",
            flush=True,
        )
        h4 = node4_snapshot_tip
        wait_until(
            "node4 mines after sync",
            lambda: n4.height() if n4.height() >= h4 + 1 else False,
            timeout=420,
            interval=3,
        )
        wait_until(
            "node2/node3 follow node4 exactly",
            lambda: all_same_tip([n2, n3, n4], max_lag=0),
            timeout=180,
            interval=3,
        )

        print(
            "\n=== Scenario 6: stop node2, restart node1 as second miner, observe two-miner convergence/orphans ===",
            flush=True,
        )
        n2_stop_height = n2.height()
        n2.crash()
        time.sleep(5)
        # Restart node1 with same data dir, now seeded to node3/node4 and still in miner mode.
        n1.genesis = False
        n1.seed = [n3.seed_addr, n4.seed_addr]
        n1.start()
        wait_until(
            "node1 reconnects",
            lambda: n1.peers() if n1.peers() >= 1 else False,
            timeout=90,
            interval=2,
        )
        wait_until(
            "two miners near-converged",
            lambda: all_same_tip([n1, n3, n4], max_lag=3),
            timeout=420,
            interval=3,
        )
        base = max(n1.height(), n4.height())
        wait_until(
            "two miners produce additional blocks",
            lambda: (
                {"n1": n1.height(), "n4": n4.height()}
                if max(n1.height(), n4.height()) >= base + 4
                else False
            ),
            timeout=300,
            interval=4,
        )
        wait_until(
            "network settles after two-miner race exactly",
            lambda: all_same_tip([n1, n3, n4], max_lag=0),
            timeout=420,
            interval=4,
        )

        snapshot_finality_tip = node4_snapshot_tip + FINALITY_DEPTH
        wait_until(
            f"tip reaches node4 snapshot finality boundary h>={snapshot_finality_tip}",
            lambda: (
                {n.name: n.height() for n in [n1, n3, n4]}
                if min(n.height() for n in [n1, n3, n4]) >= snapshot_finality_tip
                else False
            ),
            timeout=900,
            interval=5,
        )
        wait_until(
            f"node4 recursive proof advances through snapshot tip {node4_snapshot_tip}",
            lambda: (
                n4.recursive_proof_height()
                if (n4.recursive_proof_height() or 0) >= node4_snapshot_tip
                else False
            ),
            timeout=420,
            interval=3,
        )
        wait_until(
            "network settles after snapshot-finality proof advance exactly",
            lambda: all_same_tip([n1, n3, n4], max_lag=0),
            timeout=420,
            interval=4,
        )

        wait_until(
            f"node2 persisted restart gap exceeds finality depth from h={n2_stop_height}",
            lambda: (
                {n.name: n.height() for n in [n1, n3, n4]}
                if min(n.height() for n in [n1, n3, n4])
                >= n2_stop_height + FINALITY_DEPTH + 1
                else False
            ),
            timeout=900,
            interval=5,
        )
        n2_restart_tip = max(n1.height(), n3.height(), n4.height())
        print(
            f"\n=== Scenario 7: restart relay node2 and verify catch-up (gap={n2_restart_tip - n2_stop_height}) ===",
            flush=True,
        )
        n2.seed = [n1.seed_addr, n3.seed_addr, n4.seed_addr]
        n2.start()
        wait_until(
            "node2 reconnects",
            lambda: n2.peers() if n2.peers() >= 1 else False,
            timeout=90,
            interval=2,
        )
        wait_until(
            "all four nodes converge exactly",
            lambda: all_same_tip([n1, n2, n3, n4], max_lag=0),
            timeout=420,
            interval=4,
        )

        print("\n=== Final status ===", flush=True)
        for n in [n1, n2, n3, n4]:
            print(
                f"{n.name}: info={n.info()} mining={n.mining_info()} peers={n.peers()} mempool={n.mempool_size()} wallet={n.wallet_status()}",
                flush=True,
            )

        interesting = grep_logs(
            [
                "orphan",
                "reorg",
                "snapshot",
                "recursive proof",
                "mempool",
                "mined",
                "applied block",
                "validation",
                "error",
                "warn",
            ]
        )
        summary_path = BASE / "summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "final": {
                        n.name: {
                            "info": n.info(),
                            "peers": n.peers(),
                            "mempool": n.mempool_size(),
                            "mining": n.mining_info(),
                        }
                        for n in [n1, n2, n3, n4]
                    },
                    "interesting_logs": interesting,
                },
                indent=2,
            )
        )
        print(f"[summary] wrote {summary_path}", flush=True)
        print("LIVE TESTS PASSED", flush=True)
    except Exception:
        print("\n=== LIVE TEST FAILURE ===", flush=True)
        for n in started:
            print(
                f"\n--- tail {n.name} {n.log_path} ---\n{tail(n.log_path, 120)}",
                flush=True,
            )
        raise
    finally:
        cleanup(started)


if __name__ == "__main__":
    main()
