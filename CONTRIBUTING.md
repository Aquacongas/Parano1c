# Contributing to Parano1d

Bug reports and focused pull requests are welcome. Open an issue before
starting a consensus, proof-system, wire-format, storage-format, or other
protocol-level change so its scope and compatibility requirements can be
agreed first.

Report security vulnerabilities privately according to
[SECURITY.md](.github/SECURITY.md), never through a public issue or pull
request.

## Pull requests

Target the `v2` branch unless an issue specifies otherwise. Keep each pull
request limited to one logical change and describe:

- the problem and the chosen solution;
- any consensus, proof, wire, storage, wallet, or network impact;
- the tests or live scenarios used to verify it;
- any user-facing documentation that changed.

Run `cargo fmt --all -- --check` and the focused tests for every affected
crate. Do not commit wallet data, node data, generated matrix packs, build
artifacts, credentials, or private logs.

By submitting a contribution, you agree that it is licensed under the
[Apache License 2.0](LICENSE).
