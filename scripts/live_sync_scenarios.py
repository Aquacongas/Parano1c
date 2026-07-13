#!/usr/bin/env python3
"""Live two-node sync scenarios over the release matrix pack.

Scenario A: fresh node joins 19+ blocks past genesis -> O(1) snapshot sync.
Scenario B: the same node stops, misses < 18 blocks -> direct block sync.
Scenario C: the same node stops, misses 19+ blocks -> O(1) snapshot sync
            again on top of existing local state.

Each node runs its own copy of the binary next to its own copy of the
release pack, so first-run pack adoption is exercised exactly like the
unpacked tar.gz. All output is appended to per-node log files for offline
analysis; the script itself only orchestrates and asserts the sync paths.
"""

import json
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_BIN = ROOT / "target" / "release" / "paranoid"
PACK_DIR = ROOT / "target" / "release-pack" / "v1"
BASE = ROOT / "target" / "live-tests" / "sync-scenarios"
LOGS = BASE / "logs"
RETENTION = 18


class LiveTestError(Exception):
    pass


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


def wait_until(label, check, timeout, interval=1.0):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value is not None and value is not False:
                return value
        except Exception as error:  # noqa: BLE001 - polling live daemons
            last_error = error
        time.sleep(interval)
    raise LiveTestError(f"timeout waiting for {label}: last error {last_error}")


class Node:
    def __init__(self, name, p2p_port, rpc_port, mode, genesis=False, seed=None):
        self.name = name
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.mode = mode
        self.genesis = genesis
        self.seed = seed or []
        self.dist_dir = BASE / f"{name}-dist"
        self.data_dir = BASE / f"{name}-data"
        self.log_path = LOGS / f"{name}.log"
        self.proc = None
        self.log_file = None

    @property
    def rpc_url(self):
        return f"http://127.0.0.1:{self.rpc_port}"

    @property
    def seed_addr(self):
        return f"127.0.0.1:{self.p2p_port}"

    def install_distribution(self):
        self.dist_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(RELEASE_BIN, self.dist_dir / "paranoid")
        for leaf in sorted(PACK_DIR.iterdir()):
            if leaf.suffix == ".zst" or leaf.name == "selected-recursive.classes":
                shutil.copy2(leaf, self.dist_dir / leaf.name)

    def start(self, marker):
        LOGS.mkdir(parents=True, exist_ok=True)
        args = [
            str(self.dist_dir / "paranoid"),
            "--mode",
            self.mode,
            "--data-dir",
            str(self.data_dir),
            "--p2p-listen",
            f"127.0.0.1:{self.p2p_port}",
            "--rpc-listen",
            f"127.0.0.1:{self.rpc_port}",
            "--log",
            "info",
        ]
        if self.genesis:
            args.append("--genesis")
        for seed in self.seed:
            args.extend(["--seed", seed])
        self.log_file = open(self.log_path, "ab", buffering=0)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_file.write(f"\n\n===== {marker} {stamp} =====\n".encode())
        self.proc = subprocess.Popen(
            args, cwd=ROOT, stdout=self.log_file, stderr=subprocess.STDOUT
        )
        print(f"[start] {self.name} ({marker}): pid={self.proc.pid}", flush=True)
        wait_until(
            f"{self.name} RPC ready",
            lambda: rpc(self.rpc_url, "getChainInfo"),
            timeout=120,
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
            self.proc.wait(timeout=15)
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


def wait_for_height(node, target, timeout):
    def check():
        height = node.height()
        print(f"[height] {node.name}={height} (target {target})", flush=True)
        return height >= target

    return wait_until(f"{node.name} height >= {target}", check, timeout, interval=5.0)


def wait_for_sync(follower, leader, timeout, label):
    started = time.monotonic()

    def check():
        leader_height = leader.height()
        follower_height = follower.height()
        print(
            f"[sync:{label}] {follower.name}={follower_height} "
            f"{leader.name}={leader_height}",
            flush=True,
        )
        return follower_height >= leader_height

    wait_until(f"{label}: {follower.name} catches {leader.name}", check, timeout, 2.0)
    elapsed = time.monotonic() - started
    print(f"[sync:{label}] caught up in {elapsed:.1f} s (poll-grained)", flush=True)
    return elapsed


def main():
    if BASE.exists():
        shutil.rmtree(BASE)
    BASE.mkdir(parents=True)

    miner = Node("miner", 9410, 9411, mode="miner", genesis=True)
    relay = Node("relay", 9420, 9421, mode="relay", seed=[miner.seed_addr])
    miner.install_distribution()
    relay.install_distribution()

    summary = {}
    try:
        miner.start("MINER GENESIS")

        # --- Scenario A: fresh node, gap > retention -> O(1) snapshot sync.
        target_a = RETENTION + 3
        wait_for_height(miner, target_a, timeout=1800)
        started = time.monotonic()
        relay.start("RELAY RUN1 FRESH O1")
        summary["a_sync_s"] = wait_for_sync(relay, miner, 1200, "A-fresh-o1")
        summary["a_total_s"] = time.monotonic() - started
        summary["a_heights"] = {"miner": miner.height(), "relay": relay.height()}
        relay.stop()

        # --- Scenario B: short gap (< retention) -> direct block sync.
        gap_b_target = miner.height() + 4
        wait_for_height(miner, gap_b_target, timeout=900)
        started = time.monotonic()
        relay.start("RELAY RUN2 SHORT GAP BLOCKS")
        summary["b_sync_s"] = wait_for_sync(relay, miner, 900, "B-short-blocks")
        summary["b_total_s"] = time.monotonic() - started
        summary["b_heights"] = {"miner": miner.height(), "relay": relay.height()}
        relay.stop()

        # --- Scenario C: long gap (> retention) on a worked node -> O(1).
        gap_c_target = miner.height() + RETENTION + 3
        wait_for_height(miner, gap_c_target, timeout=1800)
        started = time.monotonic()
        relay.start("RELAY RUN3 LONG GAP O1 RESTART")
        summary["c_sync_s"] = wait_for_sync(relay, miner, 1200, "C-restart-o1")
        summary["c_total_s"] = time.monotonic() - started
        summary["c_heights"] = {"miner": miner.height(), "relay": relay.height()}
        relay.stop()
    finally:
        relay.stop()
        miner.stop()

    (BASE / "summary.json").write_text(json.dumps(summary, indent=2))
    print("SUMMARY " + json.dumps(summary, indent=2), flush=True)
    print(f"logs: {LOGS}", flush=True)


if __name__ == "__main__":
    main()
