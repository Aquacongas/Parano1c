# Live Agents: bounded authority across copied processes

## Question

Can independent services account for a shared, finite authorization using Parano1d v2, while each verifies the relevant network state and receipts with its own node?

The experiment gives two separately running claimant nodes the same newly generated test wallet key. Both can authorize calls on one enrolled contract instance. The contract starts with ten permits. Two execution gateways use separate node processes and separate SQLite databases. They run a fixed CPU task only after a corresponding receipt is canonical, sufficiently deep, enrolled, addressed to a locally registered job, and not previously reserved.

## Claims to test

1. Concurrent uses of one exact input produce at most one canonical successor.
2. Alternating claimant processes consume one shared quota; the eleventh use fails.
3. Restoring an earlier opening and input reference does not resurrect authority.
4. Editing a counter, using an unauthorized claimant, and closing through a disabled branch fail.
5. A second deposit with identical terms is valid on the network but is not another resource-owner authorization. Gateways reject it because it is outside their enrolled instance lineage.
6. Receipt reuse does not launch another process, including after a gateway restart.
7. A receipt for one registered executor job cannot launch a different executor's job.
8. A receipt that has not reached the experiment's finality threshold is not executable.
9. Expiry stops an unused claim; the owner's recovery branch remains usable.
10. A fresh node verifies saved call receipts after the original transaction bodies are pruned by normal retention rules.

## Enforcement boundary

The consensus relation enforces the contract transition, authority, value conservation and counter arithmetic. It does not measure GPU consumption or execute an external job. A gateway enforces the mapping from a confirmed permit to a process launch.

The gateways pin the initially enrolled output's slot and creation identifier. They independently verify each transition receipt and read the still-live successor from their own nodes, retaining a local cursor. This first prototype requires online observation of each successor. Cold reconstruction of an entire application lineage after missed transitions is a separate problem from verifying a supplied historical receipt.

Each job is registered at one gateway with a unique payout address. The receipt's authenticated payout binds its use to that local registration. The experiment uses a small fixed NOID transfer to select the job; it does not evaluate a market price for computation. The CPU workload is fixed in gateway code. No arbitrary command is accepted from an agent.

The gateway reserves a transaction identifier durably before launching the external process. A simulated crash at that boundary consumes the local reservation without completing work. Recovery refuses to retry an indeterminate launch. This tests at-most-once launch, not exactly-once completion.

## Environment and measurements

All nodes run in a loopback-only Linux network namespace, using fresh wallets and a fresh chain. The isolated profile activates v1.1 at H5 and v2 at H10. Actual wallet authorization, transaction relay, block production, recursive proof verification, persistent storage and receipt verification use the node's production paths. No mainnet account or state is used.

The claimant clients are deterministic adversarial drivers, not language models. They exercise the protocol boundary directly. The experiment does not measure a model's tendency to obey instructions or its resistance to prompt injection.

Record the source revision, source script hash, executable hashes, every permit's transaction identifier and counter change, receipt sizes and hashes, canonical race result, rejection reasons, completed and indeterminate jobs, cold synchronization time, receipt verification time, and node memory and disk measurements.

Measurements on this small local chain do not estimate mainnet synchronization, WAN latency, large live State, or long-term storage. Headers and current State remain part of a verifying node. Historical transaction bodies are pruned; their archive is not a prerequisite for the late receipt checks.

## Related work

- [FIDO Alliance, Agentic AI](https://fidoalliance.org/fido-alliance-agentic-ai/): ongoing authentication and delegated authority work.
- [Bounded Capability Receipts and Durable Spend Control for Agent Actions, draft 06](https://datatracker.ietf.org/doc/draft-schrock-ep-bounded-capability-receipts/06/): scoped capabilities and authoritative consumption state. Individual Internet-Draft, September 9, 2026. The [report](README.md) discusses its trust model.
- [AAuth Budgets, draft 00](https://mirrors.aliyun.com/ietf/draft-hardt-aauth-budgets-00.html): per-resource consumption ceilings and supervision through a person server, published September 28, 2026. This is also an Internet-Draft.

The proposed contribution is a reproducible evaluation of independent v2 verification as the shared authorization-state substrate. Quotas, idempotency, and scoped credentials already have conventional implementations. This experiment does not establish that other blockchains cannot express a quota.
