#!/usr/bin/env python3
"""Fresh public-address live test for outbound network-group diversity.

The script re-executes itself in an unprivileged network namespace, assigns
public-looking addresses to loopback, and disables mDNS. Three peers share an
IPv4 /16 while a fourth is in another /16. The target must retain the distinct
peer and one same-group peer in its two-anchor bootstrap fanout.
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
        "NOID_LIVE_OUTBOUND_DIVERSITY_DIR",
        str(RUN_PARENT / f"p2p-outbound-diversity-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_OUTBOUND_DIVERSITY_BASE_PORT", "21600"))

TARGET_IP = "11.1.0.1"
SAME_A_IP = "8.8.1.10"
SAME_B_IP = "8.8.2.20"
SAME_C_IP = "8.8.3.30"
DISTINCT_IP = "9.9.1.10"

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
    for address in (TARGET_IP, SAME_A_IP, SAME_B_IP, SAME_C_IP, DISTINCT_IP):
        subprocess.run(["ip", "addr", "add", f"{address}/32", "dev", "lo"], check=True)
    for chain in ("INPUT", "OUTPUT"):
        subprocess.run(
            ["iptables", "-A", chain, "-p", "udp", "--dport", "5353", "-j", "DROP"],
            check=True,
        )


def seed(node):
    return f"{node.p2p_host}:{node.p2p_port}"


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
    (RUN_PARENT / "LAST_P2P_OUTBOUND_DIVERSITY_RUN").write_text(str(BASE) + "\n")

    same_a = Node("same-a", BASE_PORT, BASE_PORT + 1, p2p_host=SAME_A_IP)
    same_b = Node("same-b", BASE_PORT + 10, BASE_PORT + 11, p2p_host=SAME_B_IP)
    same_c = Node("same-c", BASE_PORT + 20, BASE_PORT + 21, p2p_host=SAME_C_IP)
    distinct = Node("distinct", BASE_PORT + 30, BASE_PORT + 31, p2p_host=DISTINCT_IP)
    target = Node("target", BASE_PORT + 40, BASE_PORT + 41, p2p_host=TARGET_IP)
    nodes = [same_a, same_b, same_c, distinct, target]
    labels = {
        same_a.name: "01-same-a-fresh",
        same_b.name: "02-same-b-fresh",
        same_c.name: "03-same-c-fresh",
        distinct.name: "04-distinct-fresh",
        target.name: "05-target-four-seeds-fresh",
    }
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": live.sha256(live.NODE_BIN),
        "same_group": [SAME_A_IP, SAME_B_IP, SAME_C_IP],
        "distinct_group": DISTINCT_IP,
        "status": "running",
    }
    error = None
    try:
        same_a.start(labels[same_a.name], genesis=True)
        same_b.start(labels[same_b.name], genesis=True)
        same_c.start(labels[same_c.name], genesis=True)
        distinct.start(labels[distinct.name], genesis=True)
        target.start(
            labels[target.name],
            seeds=[seed(same_a), seed(same_b), seed(same_c), seed(distinct)],
        )

        live.wait_value(
            "two bootstrap anchors connect",
            lambda: int(rpc(target.rpc_port, "getPeerCount")) >= 2,
            timeout=60,
        )
        live.wait_value(
            "distinct /16 remains connected",
            lambda: int(rpc(distinct.rpc_port, "getPeerCount")) >= 1,
            timeout=60,
        )
        time.sleep(3)
        target_log = text(labels[target.name])
        target_peers = int(rpc(target.rpc_port, "getPeerCount"))
        same_group_live = sum(
            int(rpc(node.rpc_port, "getPeerCount")) >= 1 for node in (same_a, same_b, same_c)
        )
        require(target_peers == 2, f"target did not retain two bootstrap anchors: {target_peers}")
        require(same_group_live == 1, f"bootstrap anchors share one /16: {same_group_live}")
        require("P2P network error" not in target_log, "target P2P task failed")
        summary.update(
            {
                "status": "passed",
                "target_peer_count": target_peers,
                "same_group_servers_connected": same_group_live,
                "distinct_server_peer_count": int(rpc(distinct.rpc_port, "getPeerCount")),
            }
        )
        print(
            "[PASS] two bootstrap anchors selected from distinct /16 groups",
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
