# Agent Core

Agent Core gives an application its own verification boundary for Parano1d State and receipts. The first useful interface has two operations: inspect an exact current right and verify a supplied receipt. An agent can use both without asking an explorer or a hosted RPC provider to decide what is valid.

The original prototype in this directory is a small read-only Python interface to a locally owned full node. It does not replace that node or reduce its measured memory requirements. The separate [Agent Core implementation](https://git.parano1d.org/ignotusnemo/agcore) now owns a native Rust verifier, P2P synchronization, canonical-chain selection, authenticated current State and receipt codecs. Its Python client manages the process and typed calls without reimplementing cryptography. The [recorded demonstration](https://git.parano1d.org/ignotusnemo/agcore/src/branch/main/demo/live-agents-2026-09-30) shows three agents using independent verifier processes.

## Interface

```sh
python3 research/live_agents/agent_view.py --rpc http://127.0.0.1:9601 receipt action.receipt
python3 research/live_agents/agent_view.py --rpc http://127.0.0.1:9601 right opening.json --slot 123 --creation-id 456
```

Receipt verification returns the authenticated call, canonical tip, and finality status. It explicitly says that current ownership or spendability has not been checked. A valid receipt for an earlier call remains valid when the successor is subsequently consumed.

Current-right inspection returns the exact-instance match, current terms and counters, the height used, and the authority selected for the next call. It does not declare an external action authorized. The application also needs its enrolled grant, action binding and execution policy.

A matching instance may have an exhausted counter or reject the proposed action under its program. The caller must check the match before treating the supplied terms as live, and evaluate the exact proposed call separately. The adapter's receipt finality field uses the experiment's conservative eighteen-block depth. Readiness, peer connectivity and acceptable tip freshness must also be established by the surrounding runtime.

The research adapter accepts only literal loopback addresses and bypasses HTTP proxy environment variables. Agent Core instead uses private stdin and stdout pipes to its owned native process. That process is part of the application's trusted computing base. A malicious process with control over the verifier or its IPC can still lie to the agent; using localhost is not by itself a cryptographic identity mechanism.

## State and retained evidence

The node retains current State, permanent compact headers and bounded recent block data. It prunes historical transaction bodies. Participants retain the openings, files and receipts they need. A late participant can verify a supplied historical call without retrieving its old body from the network.

This does not promise constant total disk usage. Headers grow with chain height, and live State depends on occupied outputs and their distribution. A cold startup still authenticates the selected chain, obtains a current State snapshot, verifies the recursive terminal and applies the bounded recent suffix.

## Product boundary

A verification-only Agent Core should not load a spending secret by default. Transaction preparation can produce an exact reviewable intent, with authorization handled by a separate constrained signer. Agent-generated text cannot override a failed proof check or silently change a reviewed action.

The contract example in this directory is one application of that interface. Agent Core also serves payment receipts, funded-right discovery from supplied terms, and independent checks of a counterparty's current contract conditions. Public discovery services can supply candidates and evidence; the local verifier decides which network facts are authenticated.

Before production use, measure a cold mainnet-sized snapshot, restart time, receipt verification latency, memory, disk allocation and operation under limited peer connectivity. The isolated experiment measures only the small-chain case. Reorganization-aware application cursors and recovery after missed successor observations also need a specified protocol and dedicated tests.
