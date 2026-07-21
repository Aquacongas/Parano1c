ParanO(1)d Native Release
=========================

This archive contains the full node, command-line client, and external miner:

  paranoid        full node and built-in miner
  noid-cli        wallet and node command-line client
  noid-extminer   external proof-of-work miner

Verify the download
-------------------

Download SHA256SUMS from the same GitHub release as this archive:

  https://github.com/ignotusnemo/paranoid/releases

Before extracting or running anything, compute the archive's SHA-256 digest
and compare it with the matching line in SHA256SUMS.

Linux:

  sha256sum <downloaded-archive>

macOS:

  shasum -a 256 <downloaded-archive>

Windows PowerShell:

  Get-FileHash <downloaded-archive> -Algorithm SHA256

Never run an archive whose digest does not match.

Linux
-----

Open a terminal in the extracted directory:

  ./paranoid --help
  ./noid-cli --help
  ./noid-extminer --help

macOS
-----

If Gatekeeper blocks a verified download, remove only the quarantine
attributes from the three extracted binaries:

  xattr -d com.apple.quarantine ./paranoid
  xattr -d com.apple.quarantine ./noid-cli
  xattr -d com.apple.quarantine ./noid-extminer

If xattr reports that an attribute does not exist, no action is required.
Then run:

  ./paranoid --help

Windows
-------

If Microsoft Defender SmartScreen warns about a verified download, select
"More info" and then "Run anyway". PowerShell can also unblock all three
extracted executables at once:

  Get-ChildItem .\*.exe | Unblock-File

Then run:

  .\paranoid.exe --help

Node data
---------

The first node start creates its configuration and persistent data under:

  Linux/macOS:  ~/.paranoid/
  Windows:      %USERPROFILE%\.paranoid\

The wallet key is stored in data/wallet.key and is not password-encrypted.
Back it up and protect it before receiving funds.

Documentation: https://noid.network/
Source:        https://github.com/ignotusnemo/paranoid
