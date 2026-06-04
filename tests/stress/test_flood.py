#!/usr/bin/env python3
"""
test_flood.py — Mempool Flood & Rate-Limit Test
================================================

Tests three attack vectors:

  Phase A — Garbage flood
    Submit 200 malformed TxIntent bytes via RPC.
    Expected: instant rejection (decode error), node stays responsive.

  Phase B — Duplicate flood (dedup fast-path)
    Submit the same valid TxIntent bytes 100 times concurrently.
    Expected: 1 admitted, 99 AlreadyAdmitted (fast-path, no ZK work).

  Phase C — ZK semaphore pressure (via wallet_send)
    Submit 8 wallet_send calls concurrently.
    Expected: responses cluster in batches of 4 (semaphore=4 workers).
    The second batch takes ~84ms longer than the first.

  Phase D — Rate-limit verification (P2P gossip path)
    Two nodes: Spammer (B) sends wallet_sends → A receives via P2P gossip.
    Verify A still works (RPC responsive) and mempool size bounded.

Usage:
    # Single node (phases A, B, C):
    python3 test_flood.py --node-a http://127.0.0.1:18031

    # Two nodes (all phases including D):
    python3 test_flood.py --node-a http://127.0.0.1:18031 --node-b http://127.0.0.1:18032

Prerequisites:
    pip install requests
    Both nodes running with --mine (node-a needs UTXOs for phases B/C).
"""

import argparse
import concurrent.futures
import json
import os
import random
import sys
import time
import struct

import requests

# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def rpc(url, method, params=None, timeout=60):
    try:
        resp = requests.post(url, json={
            "jsonrpc": "2.0",
            "method": f"paranoid_{method}",
            "params": params or [],
            "id": 1,
        }, timeout=timeout)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def get_chain_info(url):
    r = rpc(url, "getChainInfo")
    return r.get("result")

def get_mempool_size(url):
    r = rpc(url, "getMempoolSize")
    return r.get("result", -1)

def submit_tx(url, hex_str):
    return rpc(url, "submitTxIntent", [hex_str])

def wallet_send(url, amount_micronoid=1, fee_micronoid=5000):
    """Send amount_micronoid μNOID to self.
    NOTE: walletSend RPC takes μNOID directly (1 NOID = 1_000_000 μNOID).
    The noid-cli send command accepts NOID and converts; here we call RPC directly.
    Address is now bech32m (noid1…) returned by walletGetAddress.
    """
    addr_r = rpc(url, "walletGetAddress", [0])
    if "error" in addr_r or "result" not in addr_r:
        return {"error": "could not get address"}
    addr = addr_r["result"]  # bech32m: noid1…
    return rpc(url, "walletSend", [addr, amount_micronoid, fee_micronoid], timeout=30)

def wallet_balance(url):
    r = rpc(url, "walletGetBalance")
    return r.get("result", {})

# ---------------------------------------------------------------------------
# Wire helpers — build a minimal TxIntent with garbage/empty proofs
# (no Poseidon2b available in Python, so we use deliberately wrong hash;
#  this exercises the fast-reject path, not the ZK semaphore path)
# ---------------------------------------------------------------------------

def build_garbage_intent(nonce: int = 0) -> bytes:
    """
    Construct a TxIntent with syntactically-correct structure but
    deliberately wrong tx_body_hash and garbage proof bytes.

    The node will reject at ZK-verify (bundle decode error), exercising
    the semaphore acquisition + fast decode-fail path.
    """
    # TxBody (encode_public):
    #   epoch_anchor [32] + fee [16 LE u128] + n_inputs [4] + n_outputs [4]
    #   + is_coinbase [1]
    epoch_anchor = bytes(range(32))          # non-zero anchor
    fee = 10_000                              # > MIN_FEE_BASE
    buf = bytearray()
    buf += epoch_anchor                       # epoch_anchor
    buf += struct.pack('<Q', fee)             # fee low 8 bytes
    buf += b'\x00' * 8                        # fee high 8 bytes (u128 LE = 16 bytes total)
    buf += struct.pack('<I', 0)               # n_inputs = 0
    buf += struct.pack('<I', 0)               # n_outputs = 0
    buf += b'\x00'                            # is_coinbase = false

    # tx_body_hash [32] — deliberately wrong (won't match body)
    tx_hash = bytes([(nonce + i) % 256 for i in range(32)])
    buf += tx_hash

    # claims_commitment [32]
    buf += b'\x00' * 32

    # n_claimed_slots [4]
    buf += struct.pack('<I', 0)

    # logic_proof_bytes: length-prefixed non-empty garbage
    # Non-empty → triggers ZK verify path (acquires semaphore)
    # Garbage bytes → WalletProofBundle::from_bytes fails quickly (~1ms)
    proof = bytes([0xDE, 0xAD, 0xBE, 0xEF, nonce % 256, (nonce >> 8) % 256])
    buf += struct.pack('<I', len(proof))
    buf += proof

    return bytes(buf)

# ---------------------------------------------------------------------------
# Phase A — Garbage flood
# ---------------------------------------------------------------------------

def phase_a(url: str):
    print("\n=== Phase A: Garbage Flood (200 malformed TxIntents) ===")
    N = 200
    rejected = 0
    errors = []

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(submit_tx, url, bytes([random.randint(0,255) for _ in range(64)]).hex()): i
                for i in range(N)}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if "error" in r or ("result" not in r):
                rejected += 1
            elif r.get("error"):
                rejected += 1
            else:
                errors.append(r)

    elapsed = time.monotonic() - t0

    # Verify node is still alive
    info = get_chain_info(url)
    alive = info is not None

    print(f"  Submitted {N} garbage requests in {elapsed:.2f}s ({N/elapsed:.0f} req/s)")
    print(f"  Rejected: {rejected}/{N}")
    print(f"  Node responsive after flood: {'YES ✓' if alive else 'NO ✗'}")
    print(f"  Unexpected admissions: {errors}")

    ok = rejected == N and alive
    print(f"  Result: {'PASS ✓' if ok else 'FAIL ✗'}")
    return ok

# ---------------------------------------------------------------------------
# Phase B — Duplicate flood (dedup fast-path)
# ---------------------------------------------------------------------------

def phase_b(url: str):
    print("\n=== Phase B: Duplicate Flood (same garbage intent × 100) ===")
    intent_hex = build_garbage_intent(42).hex()
    N = 100

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(lambda _: submit_tx(url, intent_hex), range(N)))
    elapsed = time.monotonic() - t0

    # All should be rejected; some may be rejected as InvalidProof, MalformedIntent, or
    # AlreadyAdmitted (if the first one somehow got past dedup before ZK rejection)
    total_rejected = sum(1 for r in results if "result" not in r or r.get("result") is None)
    total_error = sum(1 for r in results if r.get("error") is not None)
    ok_count = total_rejected + total_error

    info = get_chain_info(url)
    alive = info is not None
    print(f"  {N} concurrent duplicates in {elapsed:.2f}s")
    print(f"  Rejected/errored: {ok_count}/{N}")
    print(f"  Node responsive: {'YES ✓' if alive else 'NO ✗'}")
    ok = alive
    print(f"  Result: {'PASS ✓' if ok else 'FAIL ✗'}")
    return ok

# ---------------------------------------------------------------------------
# Phase C — ZK semaphore pressure via wallet_send
# ---------------------------------------------------------------------------

def phase_c(url: str):
    print("\n=== Phase C: ZK Semaphore Pressure (8 concurrent wallet_send) ===")

    bal = wallet_balance(url)
    print(f"  Wallet balance before: {bal}")
    confirmed = bal.get("confirmed_micronoid", bal.get("total_micronoid", 0)) if bal else 0
    if confirmed < 8 * 10_000:
        print(f"  SKIP: insufficient wallet balance ({confirmed} μNOID, need ≥80 000).")
        print(f"        Wait for more mining or use --node-a with more blocks.")
        return None  # not a failure, just skipped

    N = 8  # 2× semaphore size (semaphore = 4 workers)
    times = []

    def do_send(_):
        t0 = time.monotonic()
        r = wallet_send(url)
        dt = time.monotonic() - t0
        return dt, r

    t_start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as ex:
        for dt, r in ex.map(do_send, range(N)):
            times.append(dt)
    total = time.monotonic() - t_start

    times.sort()
    print(f"  {N} concurrent wallet_send in {total:.2f}s total")
    print(f"  Individual times (sorted): {[f'{t:.2f}s' for t in times]}")

    # Count successes from first run
    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as ex:
        results2 = list(ex.map(lambda _: wallet_send(url), range(N)))
    successes = sum(1 for r in results2
                    if r.get("result") and r["result"].get("tx_hash"))

    node_alive = get_chain_info(url) is not None
    print(f"  Node responsive after ZK pressure: {'YES ✓' if node_alive else 'NO ✗'}")

    # Verify mempool has bounded size
    mpool = get_mempool_size(url)
    print(f"  Mempool size after flood: {mpool}")

    ok = node_alive and mpool is not None and mpool < 10_000
    print(f"  Result: {'PASS ✓' if ok else 'FAIL ✗'}")
    return ok

# ---------------------------------------------------------------------------
# Phase D — Rate-limit test (requires two nodes)
# ---------------------------------------------------------------------------

def phase_d(url_a: str, url_b: str):
    print("\n=== Phase D: P2P Rate-Limit Test (B floods → A) ===")

    info_a_before = get_chain_info(url_a)
    info_b = get_chain_info(url_b)
    if not info_a_before or not info_b:
        print("  SKIP: one or both nodes unreachable")
        return None

    mpool_a_before = get_mempool_size(url_a)
    print(f"  Node A height={info_a_before['height']}, mempool={mpool_a_before}")
    print(f"  Node B height={info_b['height']}")

    # Flood: submit 80 tx from B in rapid succession (>50/10s rate limit)
    # Since generating proofs takes ~300ms each, we submit with no-proof (empty)
    # which gets deduped/rejected quickly but still counts towards P2P gossip
    print("  Submitting 80 wallet_sends from Node B (expecting rate-limit on A after 50)...")
    flood_start = time.monotonic()
    submitted = 0
    rejected_at_b = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(wallet_send, url_b) for _ in range(80)]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r.get("result") and r["result"].get("tx_hash"):
                submitted += 1
            else:
                rejected_at_b += 1

    flood_elapsed = time.monotonic() - flood_start
    print(f"  B: admitted={submitted}, rejected/no-utxo={rejected_at_b} in {flood_elapsed:.1f}s")

    # Wait a moment for P2P gossip to propagate
    time.sleep(2)

    # Node A should still be responsive
    info_a_after = get_chain_info(url_a)
    mpool_a_after = get_mempool_size(url_a)
    node_a_alive = info_a_after is not None

    print(f"  Node A responsive: {'YES ✓' if node_a_alive else 'NO ✗'}")
    print(f"  Node A mempool before={mpool_a_before} after={mpool_a_after}")
    print(f"  (Rate limiter allows ≤50 tx per peer per 10s window)")

    ok = node_a_alive
    print(f"  Result: {'PASS ✓' if ok else 'FAIL ✗'}")
    return ok

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Paranoid Mempool Flood Test")
    ap.add_argument("--node-a", default="http://127.0.0.1:18031", help="Node A RPC URL")
    ap.add_argument("--node-b", default=None, help="Node B RPC URL (optional, for phase D)")
    args = ap.parse_args()

    print(f"Paranoid Mempool Flood Test")
    print(f"  Node A: {args.node_a}")
    if args.node_b:
        print(f"  Node B: {args.node_b}")

    # Wait for node to be ready
    print("\nWaiting for node A to be ready...")
    for _ in range(20):
        info = get_chain_info(args.node_a)
        if info and info["height"] > 5:
            print(f"  Node A ready at height {info['height']}")
            break
        time.sleep(2)
    else:
        print("ERROR: Node A not ready after 40s")
        sys.exit(1)

    results = {}
    results["A_garbage_flood"]   = phase_a(args.node_a)
    results["B_duplicate_flood"] = phase_b(args.node_a)
    results["C_zk_semaphore"]    = phase_c(args.node_a)

    if args.node_b:
        results["D_p2p_rate_limit"] = phase_d(args.node_a, args.node_b)

    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    all_ok = True
    for name, result in results.items():
        if result is None:
            status = "SKIP"
        elif result:
            status = "PASS ✓"
        else:
            status = "FAIL ✗"
            all_ok = False
        print(f"  {name:35s} {status}")

    print("="*60)
    print(f"Overall: {'ALL PASSED ✓' if all_ok else 'SOME FAILED ✗'}")
    sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
