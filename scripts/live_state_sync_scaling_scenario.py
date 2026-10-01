#!/usr/bin/env python3
"""Exercise State transport compatibility and reuse on real chain fixtures.

Run inside an isolated network namespace, for example:
  NOID_STATE_PARENT_NETNS=$(readlink /proc/self/ns/net) \
    unshare -Urn -- python3 scripts/live_state_sync_scaling_scenario.py

Required environment: NOID_STATE_FIXTURE, NOID_STATE_NEW_BIN,
NOID_STATE_OLD_BIN, NOID_STATE_LOAD_BIN, NOID_STATE_RUN_DIR.
An optional NOID_STATE_ADVANCED_FIXTURE enables stale-state reuse checks.
The fixtures must be consistent closed MDBX copies. Wallets and identities
are never cloned. Measurements and logs stay in the explicit run directory.
"""

import concurrent.futures
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


BASE = Path(os.environ["NOID_STATE_RUN_DIR"]).resolve()
FIXTURE = Path(os.environ["NOID_STATE_FIXTURE"]).resolve()
ADVANCED = Path(os.environ.get("NOID_STATE_ADVANCED_FIXTURE", str(FIXTURE))).resolve()
NEW = Path(os.environ["NOID_STATE_NEW_BIN"]).resolve()
OLD = Path(os.environ["NOID_STATE_OLD_BIN"]).resolve()
LOAD = Path(os.environ["NOID_STATE_LOAD_BIN"]).resolve()
CLIENTS = int(os.environ.get("NOID_STATE_LOAD_CLIENTS", "96"))
LOAD_SECONDS = int(os.environ.get("NOID_STATE_LOAD_SECONDS", "120"))
live.BASE = BASE
require = live.require


class Node(live.Node):
    def __init__(self, name, port, binary):
        super().__init__(name, port, port + 1)
        self.binary = binary
        if name.startswith("source"):
            self.p2p_host = "0.0.0.0"

    def spawn(self, *args, **kwargs):
        previous = live.NODE_BIN
        live.NODE_BIN = self.binary
        try:
            return super().spawn(*args, **kwargs)
        finally:
            live.NODE_BIN = previous

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
            require(self.proc.returncode == 0, f"{self.name} did not stop cleanly")
        self._close_log()


def clone_fixture(source, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("mdbx.dat", ".network-storage-epoch"):
        shutil.copy2(source / name, destination / name)
    cache = source / "history-step-cache"
    if cache.is_dir():
        shutil.copytree(cache, destination / cache.name)


def network(delay_ms, rate_mbit):
    subprocess.run(["tc", "qdisc", "replace", "dev", "lo", "root", "netem", "delay",
                    f"{delay_ms}ms", "rate", f"{rate_mbit}mbit"], check=True)


def fields(line):
    return {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)\b", line)}


def measurements(node):
    result = {}
    terminal_time = None
    for line in node.log_text().splitlines():
        match = re.match(r"(\d\d):(\d\d):(\d\d)", line)
        clock = sum(int(value) * scale for value, scale in zip(match.groups(), [3600, 60, 1])) if match else None
        if 'phase="history_step_terminal"' in line and 'outcome="accepted"' in line:
            terminal_time = clock
        if 'phase="snapshot_segment_stage_install"' in line:
            result["state_work"] = fields(line)
            if clock is not None and terminal_time is not None:
                result["state_wall_seconds_log_resolution"] = (clock - terminal_time) % 86400
        if 'phase="snapshot_state_transfer"' in line:
            result["transfer"] = fields(line)
        if "authenticated local snapshot segments reused" in line:
            result["reuse"] = fields(line)
    return result


def rss_kb(node):
    if node.proc is None or node.proc.poll() is not None:
        return 0
    for line in Path(f"/proc/{node.proc.pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def wait_exact(source, receiver, timeout=600):
    target = source.info()
    started = time.monotonic()
    peak = 0
    healthy = []
    deadline = started + timeout
    while time.monotonic() < deadline:
        require(receiver.proc.poll() is None, f"{receiver.name} exited during sync")
        peak = max(peak, rss_kb(receiver))
        current = receiver.info(timeout=10)
        if int(current["height"]) == int(target["height"]) and current["best_hash"] == target["best_hash"]:
            source_header = live.rpc(source.rpc_port, "getBlockHeader", [target["height"]])
            receiver_header = live.rpc(receiver.rpc_port, "getBlockHeader", [target["height"]])
            require(source_header["state_root"] == receiver_header["state_root"], "final header root differs")
            require(current["active_slot_count"] == target["active_slot_count"], "live UTXO count differs")
            return {"height": target["height"], "hash": target["best_hash"], "state_root": source_header["state_root"],
                    "sync_seconds_after_rpc_ready": time.monotonic() - started, "receiver_peak_rss_kb": peak,
                    **measurements(receiver)}
        if int(time.monotonic() - started) % 10 == 0:
            status = live.rpc(source.rpc_port, "getNodeStatus", timeout=10)
            healthy.append(status["p2p_healthy"])
            require(status["p2p_healthy"], "source P2P heartbeat stalled")
        time.sleep(0.5)
    raise live.LiveForkReorgError(f"{receiver.name} did not converge to {target['height']}")


def sync_case(source, name, binary, port, warm=None, expected_version=None):
    receiver = Node(name, port, binary)
    if warm is not None:
        clone_fixture(warm, receiver.data_dir)
    started = time.monotonic()
    try:
        receiver.start(name, seeds=[source.seed])
        result = wait_exact(source, receiver)
        result["total_seconds"] = time.monotonic() - started
        result["receiver_binary_sha256"] = live.sha256(binary)
        if expected_version is not None:
            transfer = result.get("transfer", {})
            require(transfer.get(f"v{expected_version}_segments", 0) > 0, f"{name} did not negotiate v{expected_version}")
            require(transfer.get(f"v{11 - expected_version}_segments", 0) == 0, f"{name} mixed unexpected transports")
        return result
    finally:
        receiver.stop()


def load_case(source):
    height = source.height()
    load_log = BASE / "logs" / "transport-load.stderr.log"
    load_json = BASE / "transport-load.json"
    receiver = Node("receiver-under-load", 27460, NEW)
    if ADVANCED != FIXTURE:
        clone_fixture(FIXTURE, receiver.data_dir)
    # The production diversity policy reserves 32 incoming slots for public
    # network groups. Keep 96 unclassified load peers and admit the real
    # receiver through a classified address inside this isolated namespace.
    subprocess.run(["ip", "addr", "add", "8.8.0.1/32", "dev", "lo"], check=True)
    for index in range(CLIENTS):
        client_ip = f"127.2.{index}.1"
        subprocess.run(["ip", "addr", "add", f"{client_ip}/32", "dev", "lo"], check=True)
    activation = BASE / "start-state-load"
    command = [str(LOAD), f"/ip4/127.2.{{client}}.1/tcp/{source.p2p_port}", str(CLIENTS), str(LOAD_SECONDS), str(height), str(CLIENTS // 4), str(activation)]
    before = rss_kb(source)
    peak = before
    state_completed_under_load = False
    with load_json.open("wb") as output, load_log.open("wb") as errors:
        process = subprocess.Popen(command, stdout=output, stderr=errors)
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                prepared = load_log.read_text().count(": prepared")
                if prepared == CLIENTS:
                    break
                require(process.poll() is None, "load clients exited during preparation")
                time.sleep(.1)
            require(prepared == CLIENTS, "load clients did not finish bounded manifest preparation")
            receiver.start("receiver-under-load", seeds=[f"8.8.0.1:{source.p2p_port}"])
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if "snapshot HistoryStep verification started off-thread" in receiver.log_text():
                    activation.write_text("ready\n")
                    break
                require(receiver.proc.poll() is None, "receiver exited before native terminal verification")
                time.sleep(.01)
            require(activation.exists(), "receiver did not reach the State authentication boundary")
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                sync = pool.submit(wait_exact, source, receiver)
                while process.poll() is None:
                    state_completed_under_load |= bool(measurements(receiver).get("transfer"))
                    peak = max(peak, rss_kb(source))
                    status = live.rpc(source.rpc_port, "getNodeStatus", timeout=10)
                    require(status["p2p_healthy"], "State load stalled source P2P heartbeat")
                    time.sleep(1)
                require(process.returncode == 0, f"transport load exited with {process.returncode}: {load_log.read_text()[-2000:]}")
                result = sync.result(timeout=600)
            clients = json.loads(load_json.read_text())
            totals = {key: sum(client.get(key, 0) for client in clients)
                      for key in clients[0] if key != "client"}
            evidence = {"load_clients": CLIENTS, "load_seconds": LOAD_SECONDS, "totals": totals,
                        "source_initial_rss_kb": before, "source_peak_rss_kb": peak,
                        "state_completed_under_load": state_completed_under_load,
                        "verified_receiver": result}
            (BASE / "load-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
            require(totals["profile_verified"] >= CLIENTS * 3 // 4, "too few admitted load clients")
            require(totals["state_ready"] > 0 and totals["state_busy"] > 0, "State load did not exercise Ready and Busy")
            require(totals["live_ready"] > 0 and totals["header_ready"] > 0, "Live/control serving did not progress beside State")
            require(totals["v5_segments"] > 0 and totals["v6_segments"] > 0, "mixed-client load did not serve both transports")
            require(source.proc.poll() is None, "source crashed during load")
            # State deliberately has no unbounded waiter FIFO. Sustained
            # saturation can leave an honest requester on Busy until pressure
            # ends. Record that latency; exact eventual convergence, bounded
            # serving and Live/control progress remain mandatory.
            return evidence
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            receiver.stop()


def failover_case():
    """Cut a provider after verified State progress, retaining the exact plan."""
    sources = [Node(f"source-failover-{index}", 27600 + index * 10, NEW) for index in range(3)]
    receiver = Node("receiver-failover", 27640, NEW)
    for source in sources:
        clone_fixture(ADVANCED, source.data_dir)
    clone_fixture(FIXTURE, receiver.data_dir)
    identities = {}
    selected = None
    try:
        network(60, 8)
        for source in sources:
            source.start(source.name)
            match = re.search(r"loaded persistent P2P identity peer=(\S+)", source.log_text())
            require(match is not None, "source identity was not logged")
            identities[match.group(1)] = source
        require(len(identities) == 3, "source identities were accidentally cloned")
        receiver.start(receiver.name, seeds=[source.seed for source in sources])
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            match = re.search(r"snapshot segment authenticated and sealed to disk from=(\S+)", receiver.log_text())
            if match:
                selected_peer = match.group(1)
                selected = identities[selected_peer]
                selected.proc.kill()
                selected.proc.wait(timeout=10)
                selected._close_log()
                break
            require(receiver.proc.poll() is None, "receiver exited before State progress")
            time.sleep(0.01)
        require(selected is not None, "no verified network State progress before cut")
        survivor = next(source for source in sources if source is not selected)
        result = wait_exact(survivor, receiver)
        text = receiver.log_text()
        providers = re.findall(r"received state segment from=(\S+).*present=true", text)
        require(selected_peer in providers, "cut source supplied no State")
        require(any(peer != selected_peer for peer in providers), "alternate source supplied no State after cut")
        require(text.count("snapshot boundary State installed") == 1, "the immutable snapshot was installed more than once")
        require("retiring immutable candidate" not in text, "transport loss retired the authenticated candidate")
        require(result.get("transfer", {}).get("network_requests", 0) < 12, "failover discarded too much verified batch progress")
        return {"cut_source": selected.name, "state_providers": sorted(set(providers)), **result}
    finally:
        receiver.stop()
        for source in sources:
            source.stop()


def main():
    require(os.geteuid() == 0, "run in an isolated user/network namespace")
    parent_namespace = os.environ.get("NOID_STATE_PARENT_NETNS")
    require(parent_namespace is not None and os.readlink("/proc/self/ns/net") != parent_namespace,
            "an isolated network namespace is required before changing loopback traffic")
    require(not BASE.exists(), "run directory already exists")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    (BASE / "logs").mkdir(parents=True)
    summary = {"status": "running", "fixture": str(FIXTURE), "advanced_fixture": str(ADVANCED),
               "new_binary_sha256": live.sha256(NEW), "old_binary_sha256": live.sha256(OLD), "cases": {}}
    source = Node("source", 27400, OLD)
    clone_fixture(FIXTURE, source.data_dir)
    try:
        network(40, 16)
        source.start("source-old")
        summary["fixture_height"] = source.height()
        skip_compatibility = os.environ.get("NOID_STATE_SKIP_COMPATIBILITY") == "1"
        if not skip_compatibility:
            summary["cases"]["old_to_old"] = sync_case(source, "old-to-old", OLD, 27410)
            summary["cases"]["new_to_old"] = sync_case(source, "new-to-old", NEW, 27420, expected_version=5)
        source.stop()
        source.binary = NEW
        source.start("source-new")
        if not skip_compatibility:
            summary["cases"]["old_to_new"] = sync_case(source, "old-to-new", OLD, 27430)
            summary["cases"]["new_to_new"] = sync_case(source, "new-to-new", NEW, 27440, expected_version=6)
        if ADVANCED != FIXTURE:
            source.stop()
            source = Node("source-advanced", 27400, NEW)
            clone_fixture(ADVANCED, source.data_dir)
            source.start("source-advanced")
            require(source.height() - summary["fixture_height"] >= 24, "advanced fixture must be at least 24 blocks ahead")
            if os.environ.get("NOID_STATE_SKIP_WARM_CASES") != "1":
                summary["cases"]["warm_old"] = sync_case(source, "warm-old", OLD, 27448, warm=FIXTURE)
                summary["cases"]["warm_reuse"] = sync_case(source, "warm-reuse", NEW, 27450, warm=FIXTURE, expected_version=6)
                require(summary["cases"]["warm_reuse"].get("reuse", {}).get("reused_segments", 0) > 0, "warm receiver did not reuse any segment")
                summary["cases"]["warm_reuse_repeat"] = sync_case(source, "warm-reuse-repeat", NEW, 27452, warm=FIXTURE, expected_version=6)
        network(10, 32)
        summary["cases"]["mixed_load"] = load_case(source)
        if ADVANCED != FIXTURE and os.environ.get("NOID_STATE_SKIP_FAILOVER") != "1":
            source.stop()
            summary["cases"]["source_failover"] = failover_case()
        summary["status"] = "passed"
    except Exception as error:
        summary["status"] = "failed"
        summary["error"] = str(error)
        raise
    finally:
        try:
            source.stop()
        finally:
            (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
