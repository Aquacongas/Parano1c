#!/usr/bin/env python3
"""Fresh-chain connected-miner competition and restart-sync live test.

Both miners stay in one connected P2P network.  Each invocation creates empty
data directories, mines a new chain, joins miner B from h0 while A is mining,
then alternates five-block offline gaps.  The returning process always starts
in miner mode and must catch up without publishing work on a stale parent.
"""

import datetime
import json
import os
import re
import time
from pathlib import Path

import live_two_miner_fork_reorg_scenario as live


ROOT = Path(__file__).resolve().parents[1]
RUN_PARENT = ROOT / "target" / "live-tests"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
BASE = Path(
    os.environ.get(
        "NOID_LIVE_CONNECTED_MINERS_DIR",
        str(RUN_PARENT / f"connected-miner-restart-sync-clean-{STAMP}"),
    )
)
BASE_PORT = int(os.environ.get("NOID_LIVE_CONNECTED_MINERS_BASE_PORT", "20700"))
OFFLINE_GAP = 5

# Reuse the process/RPC harness while giving this scenario its own fresh root.
live.BASE = BASE
live.BASE_PORT = BASE_PORT
Node = live.Node
rpc = live.rpc
require = live.require


def exact_tip(left, right):
    return live.exact_tip(left, right)


def wait_value(label, probe, timeout, interval=0.25):
    return live.wait_value(label, probe, timeout, interval)


def wait_exact_at_least(left, right, target, timeout=900):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        a = left.info()
        b = right.info()
        state = (int(a["height"]), a["best_hash"], int(b["height"]), b["best_hash"])
        if state != last:
            print(
                f"[network-mine] {left.name}=h{a['height']} {right.name}=h{b['height']} target={target}",
                flush=True,
            )
            last = state
        if (
            int(a["height"]) >= target
            and int(a["height"]) == int(b["height"])
            and a["best_hash"] == b["best_hash"]
        ):
            result = {
                left.name: int(a["height"]),
                right.name: int(b["height"]),
                "hash": a["best_hash"],
            }
            print(f"[ok] connected miners exact at/above h{target}: {result}", flush=True)
            return result
        time.sleep(0.25)
    raise live.LiveForkReorgError(
        f"connected miners did not converge at/above h{target}; last={last}"
    )


def all_headers_match(left, right, through_height):
    return live.exact_headers(left, right, through_height)


def read_log(label):
    return (BASE / "logs" / f"{label}.log").read_text(errors="replace")


def accepted_blocks(label):
    return live.log_metrics(read_log(label))


FAILURE_MARKERS = (
    " ERROR ",
    "panicked",
    "reorg failed",
    "P2P block rejected",
    "chained orphan apply failed",
    "unknown or delayed retained-block response",
    "block sync request failed",
    "mempool sync request failed",
    "Handshake failed: input error",
)


def assert_clean(label, text):
    failures = [
        line for line in text.splitlines() if any(marker in line for marker in FAILURE_MARKERS)
    ]
    require(not failures, f"{label} contains network/consensus failures: {failures[-10:]}")


def require_miner_caught_up(label, text, minimum_applied):
    legacy_applied = text.count("applied P2P block")
    exact_applied = sum(
        int(value)
        for value in re.findall(
            r"header-first exact suffix application completed[^\n]* blocks=(\d+)",
            text,
        )
    )
    applied = legacy_applied + exact_applied
    require(applied >= minimum_applied, f"{label} applied only {applied}/{minimum_applied} blocks")
    stale_work_cancelled = (
        "prepared template parent changed before PoW" in text
        or "new chain tip: cancelling PoW to rebuild" in text
        or "canonical/template change cancelled HistoryStep preparation" in text
        or "template input changed: cancelling PoW to rebuild" in text
        or "miner: sync ready, starting" in text
        or "miner: ready, starting" in text
    )
    require(stale_work_cancelled, f"{label} has no evidence of stale mining-work cancellation")
    return {
        "applied_blocks": applied,
        "exact_suffix_blocks": exact_applied,
        "legacy_p2p_blocks": legacy_applied,
        "stale_work_cancelled": stale_work_cancelled,
    }


def logged_peer_id(text):
    match = re.search(r"loaded persistent P2P identity peer=([^\s]+)", text)
    require(match is not None, "persistent PeerId is absent from startup log")
    assert match is not None
    return match.group(1)


def main():
    require(live.NODE_BIN.is_file(), f"release node is missing: {live.NODE_BIN}")
    require(not BASE.exists(), f"run directory already exists: {BASE}")
    ports = (BASE_PORT, BASE_PORT + 1, BASE_PORT + 10, BASE_PORT + 11)
    for port in ports:
        require(live.port_is_free(port), f"port occupied: {port}")
    (BASE / "logs").mkdir(parents=True)
    (RUN_PARENT / "LAST_CONNECTED_MINERS_RUN").write_text(str(BASE) + "\n")

    binary_hash = live.sha256(live.NODE_BIN)
    print(f"[run] {BASE}", flush=True)
    print(
        f"[binary] sha256={binary_hash} size={live.NODE_BIN.stat().st_size}",
        flush=True,
    )
    miner_a = Node("miner-a", BASE_PORT, BASE_PORT + 1)
    miner_b = Node("miner-b", BASE_PORT + 10, BASE_PORT + 11)
    summary = {
        "run_dir": str(BASE),
        "binary_sha256": binary_hash,
        "binary_size": live.NODE_BIN.stat().st_size,
        "offline_gap": OFFLINE_GAP,
        "status": "running",
    }
    error = None
    try:
        # A creates the only genesis chain. B starts from its own empty h0 data
        # directory directly in miner mode while A continues to produce blocks.
        miner_a.start("01-a-fresh-genesis-live", mode="miner", genesis=True)
        live.wait_mined(miner_a, 2)
        b_initial, _ = miner_b.start(
            "02-b-fresh-miner-joins-live-a",
            mode="miner",
            genesis=True,
            seeds=[miner_a.seed],
        )
        initial_identity_hashes = {
            miner_a.name: live.sha256(miner_a.data_dir / "p2p_identity.key"),
            miner_b.name: live.sha256(miner_b.data_dir / "p2p_identity.key"),
        }
        wait_value(
            "both live miners are peers",
            lambda: int(rpc(miner_a.rpc_port, "getPeerCount")) >= 1
            and int(rpc(miner_b.rpc_port, "getPeerCount")) >= 1,
            timeout=120,
        )
        first_exact = wait_exact_at_least(miner_a, miner_b, 2, timeout=600)
        first_competition = wait_exact_at_least(
            miner_a,
            miner_b,
            int(first_exact[miner_a.name]) + 2,
            timeout=900,
        )

        # B goes offline. A mines five entirely new canonical blocks.
        miner_b.stop()
        a_before_gap = miner_a.info()
        a_gap_target = int(a_before_gap["height"]) + OFFLINE_GAP
        a_after_gap = live.wait_mined(miner_a, a_gap_target, timeout=900)

        # B returns as a miner, not as a passive node. It must sync while its
        # mining task is alive and avoid committing a stale-parent template.
        b_restart_initial, _ = miner_b.start(
            "03-b-miner-restarts-gap5-while-a-mines",
            mode="miner",
            genesis=True,
            seeds=[miner_a.seed],
        )
        b_restart_exact = wait_exact_at_least(
            miner_a,
            miner_b,
            int(a_after_gap["height"]),
            timeout=900,
        )
        second_competition = wait_exact_at_least(
            miner_a,
            miner_b,
            int(b_restart_exact[miner_a.name]) + 2,
            timeout=900,
        )

        # Swap roles: A goes offline and B alone advances another five blocks.
        miner_a.stop()
        b_before_gap = miner_b.info()
        b_gap_target = int(b_before_gap["height"]) + OFFLINE_GAP
        b_after_gap = live.wait_mined(miner_b, b_gap_target, timeout=900)

        a_restart_initial, _ = miner_a.start(
            "04-a-miner-restarts-gap5-while-b-mines",
            mode="miner",
            genesis=True,
            seeds=[miner_b.seed],
        )
        a_restart_exact = wait_exact_at_least(
            miner_a,
            miner_b,
            int(b_after_gap["height"]),
            timeout=900,
        )
        final_live = wait_exact_at_least(
            miner_a,
            miner_b,
            int(a_restart_exact[miner_a.name]) + 3,
            timeout=1200,
        )

        # Stop both from the same observed exact tip. The shutdown invariant
        # forbids either prepared template from becoming an extra block.
        miner_a.request_stop()
        miner_b.request_stop()
        miner_a.finish_stop()
        miner_b.finish_stop()

        # Reopen both persisted results only as nodes and compare every hash.
        miner_a.start("05-a-final-persisted-check")
        miner_b.start("06-b-final-persisted-check", seeds=[miner_a.seed])
        persisted_exact = wait_value(
            "persisted miner chains remain exact",
            lambda: exact_tip(miner_a, miner_b),
            timeout=300,
        )
        final_height = int(persisted_exact[miner_a.name])
        require(
            final_height == int(final_live[miner_a.name]),
            f"shutdown committed an unexpected block: live={final_live}, disk={persisted_exact}",
        )
        final_headers = wait_value(
            "all persisted canonical hashes match",
            lambda: all_headers_match(miner_a, miner_b, final_height),
            timeout=120,
        )

        phase_logs = {
            label: read_log(label)
            for label in (
                "01-a-fresh-genesis-live",
                "02-b-fresh-miner-joins-live-a",
                "03-b-miner-restarts-gap5-while-a-mines",
                "04-a-miner-restarts-gap5-while-b-mines",
                "05-a-final-persisted-check",
                "06-b-final-persisted-check",
            )
        }
        for label, text in phase_logs.items():
            assert_clean(label, text)
        peer_ids = {
            "a_initial": logged_peer_id(phase_logs["01-a-fresh-genesis-live"]),
            "a_restart": logged_peer_id(
                phase_logs["04-a-miner-restarts-gap5-while-b-mines"]
            ),
            "a_final": logged_peer_id(phase_logs["05-a-final-persisted-check"]),
            "b_initial": logged_peer_id(phase_logs["02-b-fresh-miner-joins-live-a"]),
            "b_restart": logged_peer_id(
                phase_logs["03-b-miner-restarts-gap5-while-a-mines"]
            ),
            "b_final": logged_peer_id(phase_logs["06-b-final-persisted-check"]),
        }
        require(
            len({peer_ids["a_initial"], peer_ids["a_restart"], peer_ids["a_final"]}) == 1,
            f"miner A rotated PeerId across restart: {peer_ids}",
        )
        require(
            len({peer_ids["b_initial"], peer_ids["b_restart"], peer_ids["b_final"]}) == 1,
            f"miner B rotated PeerId across restart: {peer_ids}",
        )
        final_identity_hashes = {
            miner_a.name: live.sha256(miner_a.data_dir / "p2p_identity.key"),
            miner_b.name: live.sha256(miner_b.data_dir / "p2p_identity.key"),
        }
        require(
            final_identity_hashes == initial_identity_hashes,
            "durable P2P identity bytes changed across restart",
        )
        require(
            not any("requesting snapshot" in text for text in phase_logs.values()),
            "a five-block miner restart unexpectedly used snapshot sync",
        )
        b_fresh_sync = require_miner_caught_up(
            "fresh B miner join", phase_logs["02-b-fresh-miner-joins-live-a"], 1
        )
        b_gap_sync = require_miner_caught_up(
            "B miner gap-5 restart",
            phase_logs["03-b-miner-restarts-gap5-while-a-mines"],
            OFFLINE_GAP,
        )
        a_gap_sync = require_miner_caught_up(
            "A miner gap-5 restart",
            phase_logs["04-a-miner-restarts-gap5-while-b-mines"],
            OFFLINE_GAP,
        )

        a_mined = accepted_blocks("01-a-fresh-genesis-live") + accepted_blocks(
            "04-a-miner-restarts-gap5-while-b-mines"
        )
        b_mined = accepted_blocks("02-b-fresh-miner-joins-live-a") + accepted_blocks(
            "03-b-miner-restarts-gap5-while-a-mines"
        )
        require(a_mined, "miner A never produced a block")
        require(b_mined, "miner B never produced a block")

        summary.update(
            {
                "status": "passed",
                "b_fresh_initial": b_initial,
                "first_exact": first_exact,
                "first_competition": first_competition,
                "a_before_gap": a_before_gap,
                "a_after_gap": a_after_gap,
                "b_restart_initial": b_restart_initial,
                "b_restart_exact": b_restart_exact,
                "second_competition": second_competition,
                "b_before_gap": b_before_gap,
                "b_after_gap": b_after_gap,
                "a_restart_initial": a_restart_initial,
                "a_restart_exact": a_restart_exact,
                "final_live": final_live,
                "persisted_exact": persisted_exact,
                "final_header_count": len(final_headers),
                "b_fresh_sync": b_fresh_sync,
                "b_gap_sync": b_gap_sync,
                "a_gap_sync": a_gap_sync,
                "peer_ids": peer_ids,
                "initial_identity_hashes": initial_identity_hashes,
                "final_identity_hashes": final_identity_hashes,
                "a_mined": a_mined,
                "b_mined": b_mined,
            }
        )
        print("[PASS] connected miners compete and restart-sync in miner mode", flush=True)
    except Exception as caught:
        error = caught
        summary["status"] = "failed"
        summary["error"] = str(caught)
        print(f"[FAIL] {caught}", flush=True)
    finally:
        miner_b.stop()
        miner_a.stop()
        (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"[summary] {BASE / 'summary.json'}", flush=True)
    if error is not None:
        raise error


if __name__ == "__main__":
    main()
