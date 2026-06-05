#!/usr/bin/env bash
# test_rpc.sh — RPC API test suite (pure bash + jq, no Python)
#
# Uses ports 29400/29401 to avoid conflicts with mainnet defaults.
#
# Usage:
#   bash tests/stress/test_rpc.sh             # starts own node
#   bash tests/stress/test_rpc.sh --no-node   # use existing node on :29401

set -uo pipefail

BIN="./target/release/paranoid"
CLI="./target/release/noid-cli"
RPC="http://127.0.0.1:29401"
DATA="/tmp/rpc-test-$$"
OWN_NODE=1
NODE_PID=""
PASS=0; FAIL=0

[ "${1:-}" = "--no-node" ] && OWN_NODE=0

command -v jq >/dev/null || { echo "ERROR: jq not found (apt install jq)"; exit 1; }

# ---------------------------------------------------------------------------
# Helpers — all JSON via jq, no Python
# ---------------------------------------------------------------------------

# Full JSON-RPC call
j() {
    curl -s "$RPC" -X POST -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"paranoid_${1}\",\"params\":${2:-[]}}"
}

# .result — handles false/null correctly (jq // treats false as null-like, avoid it)
r() { j "$@" | jq -r 'if .result != null then .result else "null" end'; }

# .result.<field> — handles boolean false correctly
f() { j "$1" "$2" | jq -r "if .result.${3} != null then .result.${3} else \"\" end"; }

# Integer .result
n() { j "$@" | jq -r 'if .result != null then .result else 0 end'; }

ok()  { echo "  PASS ✓  $*"; PASS=$((PASS+1)); }
ko()  { echo "  FAIL ✗  $*"; FAIL=$((FAIL+1)); }

chk() {
    local lbl=$1 val=$2 exp=${3:-__NONEMPTY__}
    if [ "$exp" = "__NONEMPTY__" ]; then
        # just check non-empty / non-null / non-false
        if [ -z "$val" ] || [ "$val" = "null" ] || [ "$val" = "false" ] || [ "$val" = "0" ]; then
            ko "$lbl  [got: $val]"
        else
            ok "$lbl"
        fi
    else
        [ "$val" = "$exp" ] && ok "$lbl" || ko "$lbl  [got='$val' want='$exp']"
    fi
}

# ---------------------------------------------------------------------------
# Node lifecycle
# ---------------------------------------------------------------------------
cleanup() {
    [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
    rm -rf "$DATA"
}
trap cleanup EXIT

if [ "$OWN_NODE" = "1" ]; then
    [ -f "$BIN" ] || { echo "ERROR: $BIN not found — run cargo build --release"; exit 1; }
    mkdir -p "$DATA"
    "$BIN" --data-dir "$DATA" --p2p-listen 0.0.0.0:29400 \
           --rpc-listen 127.0.0.1:29401 --mine --genesis \
           >"$DATA/node.log" 2>&1 &
    NODE_PID=$!
    echo "node PID=$NODE_PID"
fi

echo -n "waiting for blocks "
for i in $(seq 1 60); do
    H=$(n "blockCount")
    if [[ "$H" =~ ^[0-9]+$ ]] && [ "$H" -ge 5 ]; then echo " h=$H"; break; fi
    echo -n "."
    sleep 1
    if [ "$OWN_NODE" = "1" ] && ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo; echo "ERROR: node died"; tail -3 "$DATA/node.log"; exit 1
    fi
done

H=$(n "blockCount")
ADDR=$(r "walletGetAddress" "[0]")
echo ""
echo "=== RPC test suite  h=$H  addr=${ADDR:0:22}... ==="

# ---------------------------------------------------------------------------
echo ""
echo "--- chain ---"

chk "blockCount"                    "$H"
chk "getChainInfo.height"           "$(f "getChainInfo" "[]" "height")"
chk "getChainInfo.best_hash"        "$(f "getChainInfo" "[]" "best_hash")"
chk "getChainInfo.log_slots"        "$(f "getChainInfo" "[]" "log_slots")"

H1=$(r "getBlockHash" "[1]")
chk "getBlockHash(1) non-null"      "$H1"
chk "getBlockHash(1) len=64"        "${#H1}" "64"
chk "getBlockHash(9999) null"       "$(r "getBlockHash" "[9999]")" "null"

chk "getBlockHeader(1).hash"        "$(f "getBlockHeader" "[1]" "hash")"
MINER=$(f "getBlockHeader" "[1]" "miner")
[[ "$MINER" == noid1* ]] && ok "getBlockHeader(1).miner bech32m" || ko "getBlockHeader(1).miner bech32m  [got: $MINER]"
chk "getBlockHeader(9999) null"     "$(r "getBlockHeader" "[9999]")" "null"

chk "getHeaderByHeight(1)"          "$(r "getHeaderByHeight" "[1]")"
chk "getHeaderByHash(hash1)"        "$(r "getHeaderByHash" "[\"$H1\"]")"

# getBlock — only last 18 blocks; use recent height
RECENT=$(( H - 1 ))
BLK=$(r "getBlock" "[$RECENT]")
[ "$BLK" != "null" ] && [ -n "$BLK" ] \
    && ok "getBlock(h-1=$RECENT) non-null" \
    || ko "getBlock(h-1=$RECENT) non-null  [got: $BLK]"

chk "getSlot(0).slot_index"         "$(f "getSlot" "[0]" "slot_index")" "0"
ACTIVE=$(n "getActiveSlotCount")
[ "$ACTIVE" -gt 0 ] 2>/dev/null && ok "getActiveSlotCount=$ACTIVE > 0" || ko "getActiveSlotCount > 0  [got: $ACTIVE]"

chk "getStateInfo.log_slots"        "$(f "getStateInfo" "[]" "log_slots")"
chk "getStateInfo.fill_pct"         "$(f "getStateInfo" "[]" "fill_pct")" "0.0"
chk "getStateInfo.state_size_human" "$(f "getStateInfo" "[]" "state_size_human")"

ZERO="0000000000000000000000000000000000000000000000000000000000000000"
chk "getTx(zero) null"              "$(r "getTx" "[\"$ZERO\"]")" "null"
chk "isNullifier(zero)"             "$(r "isNullifier" "[\"$ZERO\"]")" "false"

HINTS=$(j "getSlotHints" "[4]" | jq '.result | length')
[ "${HINTS:-0}" -gt 0 ] && ok "getSlotHints(4) returned $HINTS slots" || ko "getSlotHints empty"

EA=$(r "getEpochAnchor")
chk "getEpochAnchor len=64"         "${#EA}" "64"

REC=$(r "getRecursiveProof")
[ "$REC" = "null" ] || [ "${#REC}" -gt 10 ] \
    && ok "getRecursiveProof (null-or-hex, len=${#REC})" \
    || ko "getRecursiveProof  [got: $REC]"

# ---------------------------------------------------------------------------
echo ""
echo "--- network/mining ---"

chk "getMiningInfo.height"          "$(f "getMiningInfo" "[]" "height")"
REWARD=$(f "getMiningInfo" "[]" "block_reward_micronoid")
[ "${REWARD:-0}" -gt 0 ] && ok "getMiningInfo.block_reward=$REWARD μNOID" || ko "getMiningInfo.block_reward  [got: $REWARD]"
DBITS=$(f "getMiningInfo" "[]" "difficulty_bits")
[[ "$DBITS" =~ ^[0-9]+$ ]] && ok "getMiningInfo.difficulty_bits=$DBITS" || ko "getMiningInfo.difficulty_bits  [got: $DBITS]"

PC=$(n "getPeerCount")
[[ "$PC" =~ ^[0-9]+$ ]] && ok "getPeerCount=$PC" || ko "getPeerCount  [got: $PC]"

chk "estimateFee(2)=9000"           "$(n "estimateFee" "[2]")" "9000"
chk "estimateFee(4)=13000"          "$(n "estimateFee" "[4]")" "13000"

chk "validateAddress.valid=true"    "$(f "validateAddress" "[\"$ADDR\"]" "valid")" "true"
VA_BECH=$(f "validateAddress" "[\"$ADDR\"]" "bech32")
[[ "$VA_BECH" == noid1* ]] && ok "validateAddress.bech32 starts noid1" || ko "validateAddress.bech32  [got: $VA_BECH]"
VA_HEX=$(f "validateAddress" "[\"$ADDR\"]" "hex")
chk "validateAddress.hex len=64"    "${#VA_HEX}" "64"
chk "validateAddress(bad).valid"    "$(f "validateAddress" "[\"notanaddress\"]" "valid")" "false"

# ---------------------------------------------------------------------------
echo ""
echo "--- mempool ---"

chk "getMempoolInfo.size=0"         "$(f "getMempoolInfo" "[]" "size")" "0"
FLR=$(f "getMempoolInfo" "[]" "fee_floor")
[ "${FLR:-0}" -ge 5000 ] && ok "getMempoolInfo.fee_floor=${FLR} μNOID (≥5000)" || ko "getMempoolInfo.fee_floor  [got: $FLR]"
chk "getMempoolSize=0"              "$(n "getMempoolSize")" "0"
chk "getMempoolEntry(zero) null"    "$(r "getMempoolEntry" "[\"$ZERO\"]")" "null"

# submitTxIntent with garbage → error (not a crash)
GARBAGE=$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | xxd -p | tr -d '\n' | head -c 128)
GR_ERR=$(j "submitTxIntent" "[\"$GARBAGE\"]" | jq -r 'if .error then "error" else "ok" end')
chk "submitTxIntent(garbage) → error" "$GR_ERR" "error"

# ---------------------------------------------------------------------------
echo ""
echo "--- wallet ---"

chk "walletStatus.exists"           "$(f "walletStatus" "[]" "exists")" "true"
WS_ADDR=$(f "walletStatus" "[]" "address")
[[ "$WS_ADDR" == noid1* ]] && ok "walletStatus.address bech32m" || ko "walletStatus.address  [got: $WS_ADDR]"

ADDR0=$(r "walletGetAddress" "[0]")
ADDR1=$(r "walletGetAddress" "[1]")
[[ "$ADDR0" == noid1* ]] && ok "walletGetAddress(0) bech32m" || ko "walletGetAddress(0)  [got: $ADDR0]"
[[ "$ADDR1" == noid1* ]] && ok "walletGetAddress(1) bech32m" || ko "walletGetAddress(1)  [got: $ADDR1]"
[ "$ADDR0" != "$ADDR1" ] && ok "address(0) != address(1)" || ko "address(0) != address(1)"

BAL=$(f "walletGetBalance" "[]" "total_micronoid")
[ "${BAL:-0}" -gt 0 ] && ok "walletGetBalance=$BAL μNOID" || ko "walletGetBalance > 0  [got: $BAL]"

UTXO_LEN=$(j "walletListUtxos" | jq '.result | length')
[ "${UTXO_LEN:-0}" -gt 0 ] && ok "walletListUtxos returned $UTXO_LEN UTXOs" || ko "walletListUtxos empty"
UTXO_ADDR=$(j "walletListUtxos" | jq -r '.result[0].address // ""')
[[ "$UTXO_ADDR" == noid1* ]] && ok "walletListUtxos[0].address bech32m" || ko "walletListUtxos address  [got: $UTXO_ADDR]"

SOW_LEN=$(j "getSlotsByOwner" "[\"$ADDR0\"]" | jq '.result | length')
[ "${SOW_LEN:-0}" -gt 0 ] && ok "getSlotsByOwner returned $SOW_LEN slots" || ko "getSlotsByOwner empty"

SCAN_N=$(f "walletScan" "[]" "found_utxos")
[ "${SCAN_N:-0}" -gt 0 ] && ok "walletScan found $SCAN_N UTXOs" || ko "walletScan > 0  [got: $SCAN_N]"

HIST_LEN=$(j "walletHistory" | jq '.result | length')
[[ "$HIST_LEN" =~ ^[0-9]+$ ]] && ok "walletHistory len=$HIST_LEN" || ko "walletHistory  [got: $HIST_LEN]"

# Send 1000 μNOID to self, fee=0 (auto → 9000 μNOID for 2 outputs)
SEND=$(j "walletSend" "[\"$ADDR0\", 1000, 0]")
TX=$(echo "$SEND" | jq -r '.result.tx_hash // ""')
chk "walletSend → tx_hash"          "$TX"
chk "walletSend tx_hash len=64"     "${#TX}" "64"

TX_FEE=$(echo "$SEND" | jq -r '.result.fee_micronoid // 0')
[ "${TX_FEE:-0}" -ge 9000 ] && ok "walletSend auto-fee=$TX_FEE μNOID (≥9000)" || ko "walletSend fee  [got: $TX_FEE]"

# tx in mempool
MP_HASH=$(f "getMempoolEntry" "[\"$TX\"]" "tx_hash")
chk "getMempoolEntry finds tx"      "$MP_HASH" "$TX"
chk "isNullifier(pending)=false"    "$(r "isNullifier" "[\"$TX\"]")" "false"

# Wait for confirmation — up to 60s (accommodates 5-second genesis blocks)
echo -n "  confirming tx "
for i in $(seq 1 120); do
    SZ=$(n "getMempoolSize"); [ "$SZ" = "0" ] && echo " confirmed (${i}s)" && break
    echo -n "."; sleep 0.5
done

TXI_H=$(f "getTx" "[\"$TX\"]" "height")
[ -n "$TXI_H" ] && [ "$TXI_H" != "null" ] \
    && ok "getTx.height=$TXI_H (confirmed)" \
    || ko "getTx confirmed  [got: $TXI_H]"

chk "isNullifier(confirmed)=true"   "$(r "isNullifier" "[\"$TX\"]")" "true"

# Receipt — must be while tx is still in recent blocks window
RECEIPT=$(r "walletExportReceipt" "[\"$TX\"]")
[ "$RECEIPT" != "null" ] && [ "${#RECEIPT}" -gt 20 ] \
    && ok "walletExportReceipt len=${#RECEIPT}" \
    || ko "walletExportReceipt  [got: ${RECEIPT:0:40}]"

if [ "$RECEIPT" != "null" ] && [ "${#RECEIPT}" -gt 20 ]; then
    VR=$(f "verifyReceipt" "[\"$RECEIPT\"]" "confirmed")
    chk "verifyReceipt confirmed"       "$VR" "true"
    VR_MK=$(f "verifyReceipt" "[\"$RECEIPT\"]" "merkle_valid")
    chk "verifyReceipt merkle_valid"    "$VR_MK" "true"
    # Tamper: flip 8 chars in the middle
    MID=$(( ${#RECEIPT} / 2 ))
    TAMPERED="${RECEIPT:0:$MID}deadbeef${RECEIPT:$(( MID+8 ))}"
    VT=$(f "verifyReceipt" "[\"$TAMPERED\"]" "confirmed")
    [ "$VT" = "false" ] \
        && ok "verifyReceipt tamper detected" \
        || ko "verifyReceipt tamper  [got: $VT]"
else
    ko "verifyReceipt (skipped — no receipt)"
    ko "verifyReceipt tamper (skipped)"
fi

# ---------------------------------------------------------------------------
echo ""
echo "--- mining API ---"

chk "getBlockTemplate.height"       "$(f "getBlockTemplate" "[\"$ADDR0\"]" "height")"

CORE_LEN=$(j "getBlockTemplate" "[\"$ADDR0\"]" | jq -r '.result.header_core_hex | length')
chk "header_core len=424 (212 bytes)" "$CORE_LEN" "424"

CORE_A=$(j "getBlockTemplate" "[\"$ADDR0\"]" | jq -r '.result.header_core_hex')
CORE_B=$(j "getBlockTemplate" "[\"$ADDR1\"]" | jq -r '.result.header_core_hex')
[ "$CORE_A" != "$CORE_B" ] \
    && ok "different coinbase → different header_core (block-withholding protection)" \
    || ko "block-withholding protection  [cores are equal!]"

SB_ERR=$(j "submitBlock" "[\"deadbeef\"]" | jq -r 'if .error then "error" else "ok" end')
chk "submitBlock(bad) → error"      "$SB_ERR" "error"

# ---------------------------------------------------------------------------
echo ""
echo "--- noid-cli sanity (if binary present) ---"

if [ -f "$CLI" ]; then
    C="$CLI --rpc $RPC"

    ST=$($C status 2>&1)
    echo "$ST" | grep -q "Height" && ok "cli status shows Height" || ko "cli status"

    ADDR_CLI=$($C --json address 2>/dev/null)
    [[ "$ADDR_CLI" == \"noid1* ]] && ok "cli address is bech32m" || ko "cli address  [got: ${ADDR_CLI:0:20}]"

    echo "$ST" | grep -q "Best hash" && ok "cli status shows Best hash" || ko "cli status Best hash"

    ST_CMD=$($C state 2>&1)
    echo "$ST_CMD" | grep -q "slots" && ok "cli state shows slots" || ko "cli state"

    MINE_OUT=$($C mining 2>&1)
    echo "$MINE_OUT" | grep -q "Block reward" && ok "cli mining shows Block reward" || ko "cli mining  [got: $(echo $MINE_OUT | head -c80)]"

    FEE_OUT=$($C estimate-fee 2>&1)
    echo "$FEE_OUT" | grep -q "9000" && ok "cli estimate-fee 9000" || ko "cli estimate-fee"
else
    echo "  SKIP noid-cli (binary not found)"
fi

# ---------------------------------------------------------------------------
echo ""
echo "======================================"
printf "  PASS: %d   FAIL: %d\n" "$PASS" "$FAIL"
echo "======================================"
[ "$FAIL" -eq 0 ] && echo "  ALL PASSED ✓" && exit 0 || echo "  SOME FAILED ✗" && exit 1
