#!/usr/bin/env python3
"""Fresh public-address live test for same-IP inbound Sybil fan-in.

Ten fresh PeerIds concurrently dial one public-looking target from the same
network-namespace source IP. Their advertised listen addresses remain private,
so Kademlia cannot turn the rejected inbound attempts into outbound dials. The
target must retain at most eight identities and explicitly reject the rest.
"""

import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_INBOUND_SYBIL_DIR",
        str(RUN_PARENT / f"p2p-inbound-sybil-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_INBOUND_SYBIL_BASE_PORT", "21700"))
TARGET_IP = "11.1.0.1"
ATTACKER_COUNT = 10

live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def enter_network_namespace():
    if os.environ.get("NOID_LIVE_ECLIPSE_NETNS") == "1":
        return
    env = os.environ.copy()
    env["NOID_LIVE_ECLIPSE_NETNS"] = "1"
    os.execvpe(
        "unshare",
        ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable, __file__],
        env,
    )


def configure_network():
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", f"{TARGET_IP}/32", "dev", "lo"], check=True)
    for chain in ("INPUT", "OUTPUT"):
        subprocess.run(
            ["iptables", "-A", chain, "-p", "udp", "--dport", "5353", "-j", "DROP"],
            check=True,
        )


def text(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def stop_all(nodes):
    errors = []
    for node in reversed(nodes):
        try:
            node.request_stop()
        except Exception as error:
            errors.append(f"request {node.name}: {error}")
    for node in reversed(nodes):
        try:
            node.finish_stop()
        except Exception as error:
            errors.append(f"finish {node.name}: {error}")
    return errors


def main():
    enter_network_namespace()
    configure_network()
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_P2P_INBOUND_SYBIL_RUN").write_text(str(BASE) + "\n")

    target = Node("target", BASE_PORT, BASE_PORT + 1, p2p_host=TARGET_IP)
    attackers = [
        Node(f"sybil-{index:02d}", BASE_PORT + 100 + index * 2, BASE_PORT + 101 + index * 2)
        for index in range(ATTACKER_COUNT)
    ]
    nodes = [target, *attackers]
    target_label = "01-target-fresh"
    attacker_labels = [f"02-sybil-{index:02d}-fresh" for index in range(ATTACKER_COUNT)]
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "attacker_count": ATTACKER_COUNT,
        "status": "running",
    }
    error = None
    try:
        target.start(target_label, genesis=True)
        starts = [
            attacker.spawn(label, seeds=[f"{TARGET_IP}:{target.p2p_port}"])
            for attacker, label in zip(attackers, attacker_labels)
        ]
        for attacker, label, started in zip(attackers, attacker_labels, starts):
            attacker.wait_ready(label, started)

        live.wait_value(
            "excess same-IP PeerIds are rejected",
            lambda: text(target_label).count("InboundIpFull") >= ATTACKER_COUNT - 8,
            timeout=90,
        )
        time.sleep(3)
        target_log = text(target_label)
        rejected = target_log.count("InboundIpFull")
        target_peers = int(rpc(target.rpc_port, "getPeerCount"))
        require(rejected >= ATTACKER_COUNT - 8, f"too few inbound rejections: {rejected}")
        require(target_peers <= 8, f"same public IP occupied {target_peers} peer slots")
        require(target_peers >= 1, "all inbound peers were lost")
        require("P2P network error" not in target_log, "target P2P task failed")
        summary.update(
            {
                "status": "passed",
                "inbound_ip_rejections": rejected,
                "target_peer_count": target_peers,
                "connected_attackers": sum(
                    int(rpc(node.rpc_port, "getPeerCount")) >= 1 for node in attackers
                ),
            }
        )
        print(
            f"[PASS] same-IP fan-in bounded at {target_peers}; rejections={rejected}",
            flush=True,
        )
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        cleanup = stop_all(nodes)
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
