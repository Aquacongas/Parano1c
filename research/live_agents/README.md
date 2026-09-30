# Live Agents: an agent with its own verifier

Research experiment, September 30, 2026. Parano1d v2, isolated network.

An agent should be able to establish what it is allowed to do, what authority remains, and what has already been recorded, without taking a hosted service's answer on trust. Live Agents explores that application model. [Agent Core](https://git.parano1d.org/ignotusnemo/agcore) now implements the first piece: a locally operated Parano1d verifier with a small machine-readable interface for current rights and portable receipts.

The [Live Agents demonstration](https://git.parano1d.org/ignotusnemo/agcore/src/branch/main/demo/live-agents-2026-09-30) shows three Codex CLI agents using three independent Agent Core processes against the saved isolated chain from this research. One rejects a broker's claim that a consumed grant can fund another job, one verifies a saved finalized receipt, and a fresh verifier rejects an altered receipt after the old transaction body has been pruned. [Watch the original recording](https://git.parano1d.org/ignotusnemo/agcore/raw/branch/main/demo/live-agents-2026-09-30/video.webm). The folder includes the exact tasks, raw agent logs, node logs, process topology, receipt and file hashes. The chain was prepared before filming; no new payment or contract call was made in the video.

The experiment uses a shared allowance for external computation. Two clients receive copies of the same claim key. They submit competing and sequential requests against one contract instance. Two execution gateways check the resulting permits through separate node processes before launching work. A fourth node joins from an empty directory after the old transaction bodies have been pruned and verifies the retained receipts.

## A problem

On April 28, 2026, the FIDO Alliance announced work on agent authentication, verifiable user instructions and delegated commerce. Its stated problem is practical: a service needs to establish who authorized an agent's action, under what conditions and within what limits. Google contributed AP2 and Mastercard contributed Verifiable Intent to that work. These are ongoing standards efforts involving established identity and payment providers. [FIDO announcement](https://fidoalliance.org/fido-alliance-to-develop-standards-for-trusted-ai-agent-interactions/)

NIST's August 27 discussion describes agents inheriting excessive access through user accounts, static API keys and broad scopes. It also points to existing tools such as OAuth, SPIFFE and proof-of-possession mechanisms. The problem is therefore not a lack of all authorization technology. The question for this research is how independently operated services can enforce a shared, changing allowance without making one service's database response their source of truth. [NIST: Why Agentic AI Needs a Strong Identity Foundation](https://www.nist.gov/blogs/cybersecurity-insights/back-future-why-agentic-ai-needs-strong-identity-foundation)

The September 9 revision of *Bounded Capability Receipts and Durable Spend Control for Agent Actions* states the coordination requirement particularly clearly. A portable authorization document is insufficient to enforce an aggregate budget across retries, copies and executors. Its design requires all executors to use one authoritative atomic state domain, and explicitly trusts the capability store to serialize transitions. This is an individual Internet-Draft, not an adopted IETF standard. [Draft 06, sections 1.2, 3 and 11](https://datatracker.ietf.org/doc/draft-schrock-ep-bounded-capability-receipts/06/)

That gives Live Agents a concrete research question: can a contract provide the common allowance while each participant independently verifies its state, and can participants later verify specific uses from portable evidence? This experiment evaluates that question on Parano1d. It does not implement the draft's complete authorization or delegation model.

## What Agent Core changes

Consider an agent allowed to start ten jobs across two participating compute services. Copying its workspace, restarting it, or changing the model must not turn ten jobs into twenty. Each service needs to recognize the same grant, determine whether a use was valid, and avoid executing the same authorization twice.

A centralized service can enforce that policy with a transactional database. We include that working control in this experiment. The reason to use Parano1d is that the services can instead verify the shared contract State with their own nodes. They still agree on the protocol, chain origin and which grant the resource owner enrolled; they do not need a common hosted operator to report how much authority remains.

This matters on both sides of an interaction. An agent can independently inspect a counterparty's funded terms. A resource service can independently check the permission presented by the agent. A discovery API can deliver offers, openings and receipts, but its responses do not establish their validity. Verification runs in a deterministic module outside the language model.

Two operations make the product useful:

| Agent question | Verification | Result |
| --- | --- | --- |
| Does this exact right exist now? | Authenticate current State and match the opening, slot and creation identifier | Current terms, counters, value and selected authority |
| Did this particular call occur? | Verify its contract receipt against the node's selected chain | Authenticated call, authorization and inclusion evidence |

A transaction identifier locates an event; it does not contain the evidence needed to verify it. The receipt carries evidence the recipient can check locally. A valid historical receipt and an unspent current right are deliberately separate answers.

Parano1d makes this design practical by removing historical execution replay from node startup. The node authenticates the current State through the recursive proof and verifies the recent suffix. Old transaction bodies are pruned as normal operation. The participants keep the particular receipts and terms relevant to them, so a new verifier does not acquire every old agent interaction to check one participant's evidence. This is the architectural reason for building Agent Core. [Synchronization](../../docs/architecture/synchronization.md), [contract receipts](../../docs/contracts/receipts-and-recovery.md)

The cost does not disappear: compact headers grow with chain height, State transfer depends on live occupancy, and recent block data remains. The experiment measures a small local chain. It does not establish a fixed memory or synchronization cost for mainnet or a future network.

## What we implemented

The contract is an ABI v3 custom program with two active instructions. A continuing call subtracts one from a counter and requires a fixed payout of 100,000 micronoid. Claim authority can continue but cannot close the contract. At the configured deadline, the owner's recovery branch can close it. The starting counter is ten.

Each job has a unique payout address registered at one gateway. That address binds the receipt to the selected local job. The workload is fixed by the gateway: a subprocess performs 200,000 sequential SHA-256 operations. No agent-supplied shell command is executed. The small NOID payout is part of this permit encoding; the experiment does not model compute pricing or prove that a remote provider delivered useful computation.

Enrollment pins the resource owner's exact funded instance, including its slot and creation identifier. Both gateways observe each successor through their own nodes and keep an application cursor. A second funded contract with identical terms is valid on the network but is not automatically another authorization to use the resource.

An additional [instance-binding check](check_instance_binding.py) presents that second instance's valid receipt to a gateway still at the original enrollment cursor. The public opening must match exactly, so a difference in counter values cannot explain rejection. The input instance must still be rejected because it is a different grant.

Before execution, the gateway verifies the receipt again, waits for the experiment's conservative depth of eighteen blocks, checks enrollment and the registered job, and commits a unique local reservation. The external process starts only after that durable reservation. One test injects an exception immediately after reservation; a restarted gateway refuses to retry the indeterminate permit. Network authorization and external execution remain distinct responsibilities.

The drivers are deterministic clients exercising adversarial cases. They are not language models. The gateways are separate objects with separate SQLite databases in one Python process. Their verifier nodes are separate daemon processes on one host. This isolates the protocol question; it is not a test of independent infrastructure operators or a model's resistance to prompt injection.

## Evidence

The [live run](results/2026-09-30/report.json) passed on source revision `6c96ead36c253a6e3ccf150d7a10c4ed62d1e555`. It produced 64 blocks, including the two scheduled test forks, and completed in 1,863.4 seconds. All four daemons stopped cleanly. Executable and script hashes are preserved in the report and [evidence manifest](results/2026-09-30/manifest.json).

| Check | Observed result |
| --- | --- |
| Concurrent requests from cloned claim keys | One submission succeeded; the competing submission failed with `SlotConflict`. One permit became canonical at H12. |
| Shared allowance across alternating clients | Ten continuing calls at H12-H21 reduced the counter from ten to zero. |
| Eleventh call from either client | Both preview requests failed with counter underflow. |
| Restored old opening and instance reference | Rejected as no longer matching current State. |
| Invented larger counter | Rejected as no longer matching current State. |
| Wrong authority, forbidden close, wrong payout | Rejected by call authorization, policy or program evaluation respectively. |
| Different funded instance | Its receipt verified, but the gateway rejected it. The additional check also rejected it when the original openings were identical. |
| Execution before confirmation depth | Rejected. |
| Receipt presented to the wrong executor | All ten attempts rejected. |
| Repeated execution | All ten retries rejected, then all ten rejected again after reopening the gateway databases. |
| Simulated failure after durable reservation | One permit remained reserved with no completed work; retry was refused. Nine other jobs completed. |
| Tampered receipt | Rejected by the production receipt verifier. |
| Expired claim with unused quota | Rejected. |
| Owner's recovery branch | Remaining funding recovered at H45. |
| Original bodies after normal retention | At H64, both `getBlock` and the retained-body part of `getBlockDetails` returned null for all ten permit heights. |
| Fresh verifier | Joined after pruning, matched the exact H64 tip, and verified all ten saved receipts. The original grant was no longer live. |

The concurrent-request case exercises admission of conflicting spends, not competing mined forks. The rejected calls above identify their actual RPC or application boundary; this run does not separately construct invalid recursive witnesses that bypass preflight. Reorganizations are outside this experiment.

The [instance-binding record](results/2026-09-30/instance-binding.json) establishes that identical public terms did not authorize a different funded instance. The [adapter checks](results/2026-09-30/adapter-tests.json) cover a valid historical receipt, a live current instance, a consumed original instance, corrupted evidence, refusal of a remote RPC address, and receipt verification after pruning. The [receipt files](results/2026-09-30/receipts/) are evidence from this isolated chain, not mainnet receipts.

Measurements used an Intel Core i7-1365U host with approximately 31 GiB RAM. The joining verifier was restricted by CPU affinity to three logical CPUs; no memory cap was applied. Its data directory was empty, but the operating system's page cache was not flushed. Transport was loopback. [Environment](results/environment.json)

| Measurement | Result |
| --- | ---: |
| Empty-directory startup and synchronization to H64 | 22.60 s |
| Verification of ten saved receipts | 20.05 s total |
| Per-receipt verification | 1.95-2.20 s, median 1.98 s |
| Receipt size | 912,778-918,314 bytes |
| Verifier RSS after synchronization | 657.93 MiB |
| Verifier RSS after receipt checks | 669.11 MiB |
| Verifier peak RSS reported by the process | 796.75 MiB |
| Allocated data-directory bytes after receipt checks | 25,665,536 bytes, 24.48 MiB |

The disk figure excludes the 87,367,136-byte node executable and external build artifacts. The final State contained 76 occupied slots. These measurements establish that this small-chain experiment ran on ordinary laptop hardware; they do not predict performance for larger State or a remote peer network.

The [database control](results/control.json) ran eight clients with ten requests each. Independent copies of a ten-use counter accepted eighty requests in total. A shared transactional SQLite database accepted ten. These are reference constructions, not a test of a named agent platform. They demonstrate why the common state matters and confirm that ordinary centralized accounting already solves the single-operator case.

## Application boundaries

The verified transition establishes consumption of a permit. The execution gateway still controls the external resource and must enforce its binding to that permit. A receipt does not prove that a GPU job completed, that code is correct, or that the resource owner is honest. A compromised agent can still waste authority within its permitted scope.

The current gateway requires online observation of each successor. Cold verification of a supplied call receipt works through the network verifier; cold reconstruction of the gateway's whole enrolled grant lineage is a separate application problem. Reorganization-aware cursors, missed-transition recovery and independent gateway processes need further work before deployment.

Confirmation latency also matters. Eighteen blocks correspond to nine minutes at the v2 target interval. This design fits authorizing a bounded job or session; it is not a round trip to insert before every token or low-latency tool call. A synchronized node needs adequate peer connectivity and a freshness policy. Valid proof evidence alone does not prove that an isolated node has seen the newest tip.

V2 does not supply arbitrary immediate revocation or hierarchical delegation merely because this quota example works. Its fixed authorities, branch rules, counters and bounded program are the capabilities tested here. Other systems can express counters and verify inclusion proofs; the experiment evaluates Parano1d's combination of independently validated current State, native receipts and startup without historical execution replay.

## From experiment to product

The [interface described here](AGENT_CORE.md) began as a read-only Python adapter to an operator-owned node. [Agent Core](https://git.parano1d.org/ignotusnemo/agcore) is now a separate native verifier with its own P2P synchronization, authenticated State, receipt checking and a private JSON interface. Its Python client owns the verifier process. It has no wallet, miner or signing authority. The recorded demonstration shows agents consuming those verified results; it does not claim that a receipt proves external work was delivered.

An agent runtime or service can start the verifier, establish readiness and query verified facts through the private local interface. Signing belongs behind a separate constrained action interface. The model can propose an action; it cannot turn a failed verification into authorization.

Live Agents can then build the grant, job-binding and evidence exchange protocol around those operations. The next qualification work is concrete: reorganization and missed-transition handling, independent service processes, a mainnet-sized cold startup measurement, and a hostile transport test in which altered or stale supplied data never becomes an approved action.

## Reproduce

See [PLAN.md](PLAN.md) for the hypotheses fixed before the run and [experiment.py](experiment.py) for the full harness. The node and miner use production consensus, proof, wallet, receipt and P2P paths. The isolated profile changes the test fork heights to five and ten and requires loopback-only networking.

The [recorded build inputs](results/build-inputs.json) identify the public artifacts used here. The isolated bank is `be82f3bec102f03c63715dac9bb4a939cb9aa5b21d013e38402b321fd8a41fa9`; the mainnet bank cannot substitute for it. Artifact construction and identities are recorded in the [existing isolated qualification](../v2_feasibility/results/2026-09-25-common-input-budget/REPORT.md#complete-isolated-matrix-construction). Use those test artifacts, the unchanged legacy pack and authenticated retirement keys, adjusting directory paths to the local installation. With the recorded environment variables set, build the isolated executable and miner:

```sh
cargo build --release --locked -p noid_node --features isolated-v2-fork-testnet --example isolated_v2_node -j 2
cargo build --release --locked -p noid-extminer --bin parano1d-miner -j 2
python3 research/live_agents/baseline.py --out /tmp/live-agents-control.json
NOID_V2_LIVE_DIR="$PWD/target/live-tests/live-agents-reproduction" timeout --signal=INT --kill-after=120s 3600s unshare --user --map-root-user --net python3 research/live_agents/experiment.py
```

The run directory must not exist. The recorded host has twelve logical CPUs; the current harness assigns CPU sets 0-5, 6-8 and 9-11. Linux user network namespaces, Python 3, `ip`, `taskset` and the public proof artifacts are required. All wallets and mining credentials are newly generated for this isolated chain. Do not publish wallet files when collecting evidence.

After the run has exited successfully, `collect_evidence.py RUN_DIRECTORY NEW_EVIDENCE_DIRECTORY` collects the report and public receipts, checks their hashes, and records the source-file hashes. The additional `check_instance_binding.py` runs inside the active network namespace after the main harness has recorded its foreign-instance call; use `nsenter` with the current issuer process ID, `--user --net --preserve-credentials`, and the same `NOID_V2_LIVE_DIR`. Its record is collected when present.
