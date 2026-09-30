#!/usr/bin/env python3
"""Real v2 permits, cloned claim keys, and independent execution gateways.

Run from a loopback-only network namespace with NOID_V2_LIVE_DIR pointing
to a fresh directory. Uses the separately built isolated_v2_node. No mocks
replace consensus, wallet proofs, receipt verification, storage, or P2P.
"""
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import sqlite3
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
if "NOID_V2_LIVE_DIR" not in os.environ:
    raise SystemExit("Set NOID_V2_LIVE_DIR to a fresh experiment directory")
import live_v2_contract_scenario as chain

live, rpc, BASE = chain.live, chain.rpc, chain.BASE
QUOTA = 10
JOB_PAYMENT = 100_000
FINALITY_DEPTH = 18
WORK = "import hashlib; x=b'live-agents-v1';\nfor _ in range(200000): x=hashlib.sha256(x).digest()\nprint(x.hex())"


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def node_resources(node):
    status = Path(f"/proc/{node.proc.pid}/status").read_text()
    memory = {line.split(':')[0]:line.split(':')[1].strip() for line in status.splitlines()
              if line.startswith(("VmRSS:", "VmHWM:", "Threads:"))}
    files = [p for p in node.data_dir.rglob('*') if p.is_file()]
    return {"process":memory,"data_file_bytes":sum(p.stat().st_size for p in files),
            "data_allocated_bytes":sum(p.stat().st_blocks*512 for p in files),
            "file_count":len(files)}


def receipt_page(encoded):
    """Extract identifiers only AFTER the production RPC verified this blob.

    Wire references: noid_block/contract_receipt.rs and noid_tx/paged_spend.rs.
    This is not a second cryptographic verifier.
    """
    raw = bytes.fromhex(encoded)
    live.require(raw[:8] in (b"O1OBJRC4", b"O1OBJRC5"), "receipt version")
    page = raw[8 + 699:8 + 699 + 323]
    slot, amount, creation = struct.unpack_from("<IQQ", page, 72)
    output_slot, retained = struct.unpack_from("<IQ", page, 232)
    return {"input_slot": slot, "input_amount": amount,
            "input_creation": creation, "output_slot": output_slot,
            "retained": retained}


class Denied(Exception):
    pass


class Gateway:
    """Online grant tracker and durable at-most-once local process launcher.

    Each gateway owns its own database and uses its own node. Enrollment is
    trusted provisioning by the resource owner. No agent assertion can enroll
    another grant. This first experiment tracks each successor while live.
    """
    def __init__(self, name, node, original, slot):
        self.name, self.node = name, node
        self.directory = BASE / name
        self.directory.mkdir(exist_ok=True)
        self.db = sqlite3.connect(self.directory / "gateway.sqlite")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs(address TEXT PRIMARY KEY, job TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS permits(txid TEXT PRIMARY KEY, details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS launches(txid TEXT PRIMARY KEY, state TEXT NOT NULL, result TEXT);
        """)
        if self.db.execute("SELECT v FROM meta WHERE k='cursor'").fetchone() is None:
            self.db.execute("INSERT INTO meta VALUES('cursor',?)", (json.dumps({"opening":original,"slot":slot}),))
            self.db.commit()

    def cursor(self):
        return json.loads(self.db.execute("SELECT v FROM meta WHERE k='cursor'").fetchone()[0])

    def register_job(self, address, job):
        self.db.execute("INSERT INTO jobs VALUES(?,?)", (address, job))
        self.db.commit()

    def observe(self, encoded):
        checked = rpc(self.node, "verifyObjectReceipt", [encoded])
        if not checked["valid"] or checked["terminal"]:
            raise Denied("not_a_continuing_permit")
        page, previous = receipt_page(encoded), self.cursor()
        if (checked["original"]["opening_hex"] != previous["opening"]["opening_hex"]
                or page["input_slot"] != previous["slot"]["slot_index"]
                or page["input_creation"] != previous["slot"]["creation_id"]):
            raise Denied("outside_enrolled_instance_lineage")
        if int(checked["successor"]["state"][0]) != int(checked["original"]["state"][0]) - 1:
            raise Denied("incorrect_permit_transition")
        successor = rpc(self.node, "getObjectStatus", [checked["successor"]["opening_hex"], page["output_slot"]])
        if (not successor["matches_opening"] or successor["slot"]["empty"]
                or successor["slot"]["value"] != page["retained"]):
            raise Denied("successor_not_live_at_observation")
        self.db.execute("INSERT INTO permits VALUES(?,?)", (checked["txid"], json.dumps(checked)))
        self.db.execute("UPDATE meta SET v=? WHERE k='cursor'", (json.dumps({"opening":checked["successor"],"slot":successor["slot"]}),))
        self.db.commit()
        return checked

    def execute(self, encoded, crash_before_effect=False):
        start = time.monotonic()
        checked = rpc(self.node, "verifyObjectReceipt", [encoded])
        if not checked["valid"]:
            raise Denied("invalid_receipt")
        if self.node.height() - checked["height"] < FINALITY_DEPTH:
            raise Denied("not_final")
        if not self.db.execute("SELECT 1 FROM permits WHERE txid=?", (checked["txid"],)).fetchone():
            raise Denied("not_an_enrolled_permit")
        payout = checked["payout"]
        job = self.db.execute("SELECT job FROM jobs WHERE address=?", (payout["address"],)).fetchone() if payout else None
        if job is None:
            raise Denied("not_this_executor_job")
        try:
            self.db.execute("INSERT INTO launches VALUES(?, 'reserved', NULL)", (checked["txid"],))
            self.db.commit()
        except sqlite3.IntegrityError:
            raise Denied("permit_already_reserved_or_used")
        if crash_before_effect:
            raise Denied("injected_crash_after_durable_reservation")
        output = subprocess.check_output([sys.executable, "-c", WORK], text=True, timeout=30).strip()
        self.db.execute("UPDATE launches SET state='completed', result=? WHERE txid=?", (output, checked["txid"]))
        self.db.commit()
        return {"gateway":self.name,"job":job[0],"txid":checked["txid"],"result":output,
                "verification_and_job_seconds":time.monotonic()-start}

    def close(self):
        self.db.close()


def main():
    devices = [line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    live.require(devices == ["lo"], "requires loopback-only namespace")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    live.require(not BASE.exists(), "fresh run directory required")
    BASE.mkdir(parents=True, mode=0o700)
    (BASE / "logs").mkdir()
    (BASE / "receipts").mkdir()
    key = BASE / "mining.key"
    key.write_text(secrets.token_hex(32) + "\n")
    key.chmod(0o600)
    live.BASE = BASE
    issuer = chain.Node("issuer", 26600, 26601, command_prefix=("taskset","-c","0,1,2,3,4,5"))
    left = chain.Node("agent-a", 26610, 26611, command_prefix=("taskset","-c","6,7,8"))
    right = chain.Node("agent-b", 26620, 26621, command_prefix=("taskset","-c","9,10,11"))
    late = chain.Node("late-verifier", 26630, 26631, command_prefix=("taskset","-c","6,7,8"))
    nodes, gateways = [issuer,left,right,late], []
    started = time.monotonic()
    report = {"status":"running","quota":QUOTA,"events":[],"blocks":[],"permits":[],"jobs":[],
              "source_head":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
              "script_sha256":live.sha256(__file__),"host":platform.platform(),
              "binary_sha256":{p.name:live.sha256(p) for p in (chain.NODE,chain.MINER)},
              "fork_heights":[5,10],"llm_models_used":False,
              "workload":"200000 sequential SHA-256 operations per authorized subprocess"}

    def checkpoint(stage):
        report["stage"] = stage
        report["elapsed_seconds"] = time.monotonic()-started
        write_json(BASE / "report.json", report)
        print("[stage] " + stage, flush=True)

    def rejected(label, operation):
        try:
            operation()
        except (live.LiveForkReorgError, Denied) as error:
            live.require("transport failed" not in str(error), str(error))
            value = {"case":label,"outcome":"rejected","reason":str(error)}
            report["events"].append(value)
            print("[reject] " + label + ": " + str(error)[:140], flush=True)
            return value
        raise live.LiveForkReorgError("unexpected acceptance: " + label)

    def converge():
        for node in (left,right):
            if node.proc is not None and node.proc.poll() is None:
                live.wait_value(node.name+" converged", lambda node=node: live.exact_tip(issuer,node),600)

    def mine(count=1):
        first, begin = issuer.height()+1, time.monotonic()
        checkpoint(f"mine H{first}..H{first+count-1}")
        with (BASE / "logs" / f"miner-{first}.log").open("w") as log:
            result = subprocess.run([str(chain.MINER),"--rpc",f"http://127.0.0.1:{issuer.rpc_port}",
                "--key-file",str(key),"--threads","2","--rpc-timeout","600","--blocks",str(count)],
                cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=max(1200,count*120))
        live.require(result.returncode == 0 and issuer.height() == first+count-1,"mining failed")
        converge()
        report["blocks"].append({"first":first,"last":issuer.height(),"seconds":time.monotonic()-begin})

    def definition(authority, owner, limit, deadline):
        return {"kind":"custom_program","definition":{
            "state":[str(limit),"0"],"program":[
                {"opcode":"subtract","destination":"state0","left":"state0","right":"one",
                 "predicate":{"source":"terminal","inverted":True},"immediate":"0"},
                {"opcode":"assert_equal","destination":"scratch0","left":"payout","right":"immediate",
                 "predicate":{"source":"terminal","inverted":True},"immediate":str(JOB_PAYMENT)}],
            "claim_authority":authority,"recovery_authority":owner,"claim_recipient":owner,"recovery_recipient":owner,
            "deadline_height":deadline,"max_fee_micronoid":1000000,"max_payout_micronoid":JOB_PAYMENT,
            "min_retained_micronoid":1000000,"claim_can_continue":True,"claim_can_close":False,
            "recovery_can_continue":False,"recovery_can_close":True,"unrestricted_payout_recipient":True}}

    def request(info, slot, recipient, terminal=False):
        return {"opening_hex":info["opening_hex"],"slot_index":slot["slot_index"],"creation_id":slot["creation_id"],
                "terminal":terminal,"payout":None if terminal else {"address":recipient,"amount_micronoid":JOB_PAYMENT},
                "fee_micronoid":0}

    def submit(node, payload):
        reviewed = rpc(node,"previewObjectCall",[payload])
        guarded = dict(payload, expected_authority=rpc(node,"walletActiveAddress")["address"],
            expected_txid=reviewed["txid"],expected_call_height=reviewed["call_height"],expected_recovery=reviewed["recovery"])
        return rpc(node,"walletCallObject",[guarded])

    def address():
        return rpc(issuer,"walletNextAddress")["address"]

    try:
        checkpoint("start issuer and one claimant; clone only the isolated claimant wallet")
        left.start("01-agent-a")
        right.data_dir.mkdir(parents=True)
        shutil.copy2(left.data_dir / "wallet.key", right.data_dir / "wallet.key")
        if (left.data_dir / "wallet.meta").exists():
            shutil.copy2(left.data_dir / "wallet.meta", right.data_dir / "wallet.meta")
        right.start("02-agent-b")
        issuer.start("03-issuer",mode="extminer",genesis=True,seeds=[left.seed,right.seed])
        owner = rpc(issuer,"walletActiveAddress")["address"]
        claimant = rpc(left,"walletActiveAddress")["address"]
        live.require(claimant == rpc(right,"walletActiveAddress")["address"] and owner != claimant,"claimant cloning failed")
        report.update(owner=owner,claimant=claimant)
        mine(10)
        live.require(rpc(issuer,"getContractProtocol")["active_at_next_block"],"v2 not active")
        terms = definition(claimant,owner,QUOTA,44)
        original = rpc(issuer,"createObject",[terms])
        expiry = rpc(issuer,"createObject",[definition(claimant,owner,5,30)])
        for node in (issuer,left,right):
            rpc(node,"walletWatchObject",[original["opening_hex"]])
            rpc(node,"walletWatchObject",[expiry["opening_hex"]])
        funding = rpc(issuer,"walletFundObject",[original["opening_hex"],100000000,0])
        extra = rpc(issuer,"walletFundObject",[original["opening_hex"],10000000,0])
        exp_funding = rpc(issuer,"walletFundObject",[expiry["opening_hex"],20000000,0])
        mine()
        original_slot = chain.output_for(issuer,funding["txid"],original["address"])
        extra_slot = chain.output_for(issuer,extra["txid"],original["address"])
        expiry_slot = chain.output_for(issuer,exp_funding["txid"],expiry["address"])
        live.require(all(x is not None for x in (original_slot,extra_slot,expiry_slot)),"funded slots absent")
        report["enrollment"] = {"opening":original,"slot":original_slot,"funding_txid":funding["txid"]}
        write_json(BASE / "saved-agent-state.json",report["enrollment"])
        gateways = [Gateway("executor-a",left,original,original_slot), Gateway("executor-b",right,original,original_slot)]
        job_addresses = []
        for i in range(12):
            addr = address()
            gateway = gateways[i % 2]
            gateway.register_job(addr,f"fixed-compute-{i}")
            job_addresses.append(addr)
        current, slot = original, original_slot
        stale_request = request(current,slot,job_addresses[0])
        rejected("wrong_claim_authority", lambda: rpc(issuer,"walletCallObject",[stale_request]))
        rejected("claimant_cannot_close", lambda: rpc(left,"walletCallObject",[request(current,slot,None,True)]))
        wrong_amount = copy.deepcopy(stale_request)
        wrong_amount["payout"]["amount_micronoid"] += 1
        rejected("wrong_job_payment",lambda: rpc(left,"previewObjectCall",[wrong_amount]))

        def capture(result, prior):
            txid = result["transaction"]["txid"]
            encoded = rpc(issuer,"exportObjectReceipt",[prior["opening_hex"],txid])
            (BASE / "receipts" / (txid+".receipt")).write_bytes(bytes.fromhex(encoded))
            checks = [g.observe(encoded) for g in gateways]
            live.require(checks[0] == checks[1],"independent gateway verification differs")
            checked = checks[0]
            report["permits"].append({"txid":txid,"height":checked["height"],"before":prior["state"][0],
                "after":checked["successor"]["state"][0],"payout":checked["payout"],
                "receipt_bytes":len(encoded)//2,"receipt_sha256":hashlib.sha256(bytes.fromhex(encoded)).hexdigest()})
            return checked["successor"], gateways[0].cursor()["slot"], encoded

        checkpoint("two cloned claimants concurrently consume the same exact instance")
        barrier = __import__('threading').Barrier(2)
        def compete(pair):
            node,addr = pair
            barrier.wait()
            try: return {"node":node.name,"accepted":True,"result":submit(node,request(current,slot,addr))}
            except live.LiveForkReorgError as error:
                live.require("transport failed" not in str(error),str(error))
                return {"node":node.name,"accepted":False,"reason":str(error)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            candidates = list(pool.map(compete,[(left,job_addresses[0]),(right,job_addresses[1])]))
        report["race"] = candidates
        live.require(any(c["accepted"] for c in candidates),"neither race candidate submitted")
        live.wait_value("producer has one candidate",lambda: any(rpc(issuer,"getMempoolEntry",[c["result"]["transaction"]["txid"]]) for c in candidates if c["accepted"]),120)
        mine()
        mined_ids = {t["txid"] for t in rpc(issuer,"getBlockDetails",[issuer.height()])["retained"]["transactions"]}
        winners = [c for c in candidates if c["accepted"] and c["result"]["transaction"]["txid"] in mined_ids]
        live.require(len(winners)==1,"race did not yield exactly one canonical permit")
        report["race_canonical_permits"] = len(winners)
        current,slot,first_receipt = capture(winners[0]["result"],current)
        receipts = [first_receipt]
        rejected("execute_before_finality",lambda: gateways[0].execute(first_receipt))
        rejected("restored_agent_state",lambda: submit(right,stale_request))
        changed = copy.deepcopy(terms)
        changed["definition"]["state"][0] = "1000"
        fake = rpc(left,"createObject",[changed])
        rejected("invented_larger_counter",lambda: submit(left,request(fake,slot,job_addresses[2])))
        for index in range(1,QUOTA):
            checkpoint(f"consume permit {index+1}/{QUOTA} through alternating claimant nodes")
            result = submit((left,right)[index%2],request(current,slot,job_addresses[index+1]))
            live.wait_value("permit reaches producer",lambda: rpc(issuer,"getMempoolEntry",[result["transaction"]["txid"]]) is not None,120)
            mine()
            current,slot,encoded = capture(result,current)
            receipts.append(encoded)
        for node in (left,right):
            rejected("exhausted_quota_"+node.name,lambda node=node: submit(node,request(current,slot,job_addresses[11])))
        live.require(current["state"][0]=="0","quota not exhausted")
        checkpoint("valid second funding must not become another enrolled grant")
        foreign = submit(left,request(original,extra_slot,job_addresses[11]))
        live.wait_value("foreign instance reaches producer",lambda: rpc(issuer,"getMempoolEntry",[foreign["transaction"]["txid"]]) is not None,120)
        mine()
        foreign_receipt = rpc(issuer,"exportObjectReceipt",[original["opening_hex"],foreign["transaction"]["txid"]])
        live.require(rpc(right,"verifyObjectReceipt",[foreign_receipt])["valid"],"foreign funded instance should be valid on chain")
        rejected("valid_unenrolled_instance",lambda: gateways[0].observe(foreign_receipt))
        report["foreign_instance"]={"txid":foreign["transaction"]["txid"],"network_valid":True,"gateway_authorized":False}
        mine(max(p["height"] for p in report["permits"])+FINALITY_DEPTH-issuer.height())
        rejected("expired_claim_with_unused_quota",lambda: submit(left,request(expiry,expiry_slot,job_addresses[11])))
        checkpoint("execute real jobs using finalized receipts and separate durable gateway databases")
        for i,encoded in enumerate(receipts):
            verified = rpc(left,"verifyObjectReceipt",[encoded])
            recipient = verified["payout"]["address"]
            g = next(g for g in gateways if g.db.execute("SELECT 1 FROM jobs WHERE address=?",(recipient,)).fetchone())
            other = next(other for other in gateways if other is not g)
            rejected(f"receipt_wrong_executor_{i}",lambda: other.execute(encoded))
            if i==len(receipts)-1:
                rejected("crash_after_reservation",lambda: g.execute(encoded,crash_before_effect=True))
            else:
                report["jobs"].append(g.execute(encoded))
            rejected(f"receipt_replay_{i}",lambda: g.execute(encoded))
        corrupted = bytearray.fromhex(first_receipt)
        corrupted[20] ^= 1
        rejected("tampered_receipt",lambda: gateways[0].execute(corrupted.hex()))
        for i,g in enumerate(gateways):
            name,node=g.name,g.node
            g.close()
            gateways[i]=Gateway(name,node,original,original_slot)
        for i,encoded in enumerate(receipts):
            v=rpc(left,"verifyObjectReceipt",[encoded])
            g=next(g for g in gateways if g.db.execute("SELECT 1 FROM jobs WHERE address=?",(v["payout"]["address"],)).fetchone())
            rejected(f"gateway_restart_replay_{i}",lambda: g.execute(encoded))

        checkpoint("advance through normal body pruning; recover unused funding")
        mine(44-issuer.height())
        recovered=submit(issuer,request(current,slot,None,True))
        mine()
        report["recovery"]={"txid":recovered["transaction"]["txid"],"height":issuer.height()}
        mine(max(p["height"] for p in report["permits"])+43-issuer.height())
        report["pruning_checks"]=[]
        for p in report["permits"]:
            live.require(rpc(issuer,"getBlock",[p["height"]]) is None,"original block still served")
            live.require(rpc(issuer,"getBlockDetails",[p["height"]])["retained"] is None,"retained body remains")
            report["pruning_checks"].append({"height":p["height"],"raw_block":None,"retained_body":None})
        checkpoint("fresh verifier joins after original permit bodies have been pruned")
        begin=time.monotonic()
        late.start("04-late-verifier",seeds=[issuer.seed])
        live.wait_value("fresh verifier catches exact tip",lambda: live.exact_tip(issuer,late),900)
        report["late_sync_seconds"]=time.monotonic()-begin
        report["late_resources_after_sync"]=node_resources(late)
        report["late_receipt_checks"]=[]
        for p,encoded in zip(report["permits"],receipts):
            begin=time.monotonic()
            checked=rpc(late,"verifyObjectReceipt",[encoded])
            live.require(checked["valid"] and checked["txid"]==p["txid"],"cold receipt verification failed")
            report["late_receipt_checks"].append({"txid":checked["txid"],"seconds":time.monotonic()-begin})
        report["late_resources_after_receipts"]=node_resources(late)
        old=rpc(late,"getObjectStatus",[original["opening_hex"],original_slot["slot_index"]])
        report["late_original_status"]={"matches_opening":old["matches_opening"],"slot":old["slot"]}
        live.require(not old["matches_opening"] or old["slot"]["creation_id"]!=original_slot["creation_id"],"old grant resurrected")
        report["launch_counts"]={}
        for g in gateways:
            report["launch_counts"][g.name]={state:n for state,n in g.db.execute("SELECT state,count(*) FROM launches GROUP BY state")}
        live.require(len(report["jobs"])==QUOTA-1,"unexpected completed job count")
        report.update(status="passed",final_tip=issuer.info())
        checkpoint("complete")
    except BaseException as error:
        report.update(status="failed",error=repr(error))
        checkpoint("failed")
        raise
    finally:
        for node in nodes: node.request_stop()
        for node in nodes:
            try: node.finish_stop()
            except Exception as error: report.setdefault("shutdown_errors",[]).append(str(error))
        for g in gateways:
            try: g.close()
            except Exception: pass
        report["elapsed_seconds"]=time.monotonic()-started
        write_json(BASE / "report.json",report)


if __name__ == "__main__":
    main()
