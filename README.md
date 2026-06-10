## PSA: Critical P2Pool security update

A critical vulnerability has been discovered in all currently released P2Pool versions.

This is a P2Pool consensus bug that can allow an attacker to affect the calculated payouts of miners - up to the whole block reward going to the attacker.

To avoid facilitating exploitation, no technical details will be published at this time. The vulnerability **does not** enable RCE (remote code execution), node crashes, or resource-exhaustion attacks. However, affected nodes remain financially vulnerable until updated.

A patched P2Pool release will be published on **2026-06-13 (this Saturday) at 15:00 UTC**. All users must update as soon as the release becomes available.

Anyone continuing to run an older version after that time risks losing mining payouts if the vulnerability is exploited. **Note that mining payouts which are already in your wallet are safe.** Updating is strongly recommended even if your node appears to be operating normally.

Source code, signed binaries, checksums, and upgrade instructions will be published through the official P2Pool release channels only - https://github.com/SChernykh/p2pool/releases

**Download releases only from the official page and verify all downloaded files before installation.**

Because P2Pool is open source, the fix will become visible once published. A capable attacker may be able to develop an exploit within hours, leaving miners who have not updated exposed.

**It is essential that you are available to update promptly at the time of the release, or have a carefully tested automatic update process that downloads, verifies, and installs the official release.**

Further technical details will be disclosed after sufficient adoption of the patched release.

**We are continuously monitoring the network and have reviewed the available historical logs. We have found no evidence that this vulnerability has been exploited.**
