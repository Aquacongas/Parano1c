# Security

## Supported versions

| Release line | Security support |
|---|---|
| `1.0.x` mainnet | Supported |

Security fixes are published for the current mainnet release line. Node
operators and wallet users should run its latest patch release.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting to submit a finding: open
the Parano1d repository, select **Security and quality**, then **Report a
vulnerability**. If that is unavailable, email <dev@parano1d.org>. Do not open
a public issue or discuss an unpatched vulnerability in a public channel.

Every report must include:

- the affected mainnet release or exact commit, component, platform, and code
  path;
- the expected behavior, observed behavior, and concrete mainnet impact;
- a reliable reproducer, test vector, proof of concept, trace, or other evidence
  that lets us reproduce the defect and verify its impact;
- a NOID payout address.

A patch is welcome but not required. Reports that do not identify a concrete
defect and provide enough evidence to verify it may be closed without further
investigation. We will confirm receipt, assess qualifying reports, implement the
final fix, and coordinate disclosure with the reporter.

## Parano1d Bug Hunt ①

Parano1d pays for previously unknown, reproducible bugs that exist in the
unmodified current mainnet release or its official release artifacts. A test
harness or instrumentation may be used to demonstrate a bug, but the defect
itself must exist without changing Parano1d's validation or consensus rules.

| Reward | Finding |
|---:|---|
| **500 NOID** | A confirmed non-critical mainnet bug with material impact on the correctness, reliability, or security of Parano1d. |
| **10,000 NOID** | A confirmed vulnerability with at least one of the critical outcomes defined below. |

Critical means the report demonstrates that the unmodified current mainnet
release can:

- accept an invalid State or proof;
- allow unauthorized spending or issuance;
- disclose a wallet secret without its owner's authorization;
- execute attacker-controlled code remotely in official software;
- deterministically split unmodified mainnet nodes or halt the network as a
  whole.

The reward tier is based on demonstrated impact, not the most severe
hypothetical outcome. Temporary peer loss, slow synchronization, orphaned
blocks, hardware performance, or degraded liveness do not by themselves meet
the critical tier, although an underlying reproducible code defect may still
qualify for 500 NOID.

### Eligible reports

- affect the current mainnet release or its official release artifacts;
- identify a concrete defect rather than a possible improvement;
- name the affected release or exact commit and code path;
- explain the real impact and provide a reliable reproducer, test vector, or
  other evidence that lets us verify it;
- remain private until a fix is available and disclosure is coordinated with
  us;
- are the first complete report of a previously unknown issue.

### Not eligible

- feature requests, protocol redesigns, upgrade proposals, or suggestions for
  new functionality;
- performance and optimization suggestions without a reproducible defect;
- behavior caused only by removing or changing local validation, proof, or
  consensus checks;
- expected protocol behavior, user or configuration errors, hardware limits,
  ISP or VPN restrictions, unless a defect in official Parano1d software is
  demonstrated;
- refactoring, naming, style, or documentation suggestions without an
  underlying code defect;
- cosmetic UI, wording, logging, or telemetry issues without material
  operational or security impact;
- vague concerns, speculative issue lists, or claims without evidence;
- upstream dependency reports without demonstrated impact through the current
  mainnet release;
- known issues, duplicates, public disclosure before coordinated remediation,
  and third-party pools, miners, or other software outside this repository.

Automated tools and AI may be used, but every claim must be verified against
the exact mainnet code and supported by reproducible evidence. Raw model
output, scanner output, speculative audit lists, and unverified claims are not
eligible. We do not turn a list of possible concerns into a reproducer for the
reporter.

Submit one underlying defect per report. Multiple symptoms, variants, affected
locations, or reports caused by the same root defect receive one reward. The
first complete and reproducible private report has priority; an earlier vague
warning or automated output does not reserve a reward.

Submission alone does not guarantee payment. After the defect and its impact
are reproduced and confirmed, we assign its reward tier and pay the NOID
address provided in the report. Rewards are paid in NOID with no promised fiat
equivalent. Confirmed findings are disclosed after the fix is available, with
credit to the reporter unless they choose to remain anonymous.
