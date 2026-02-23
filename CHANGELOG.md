# VoteSecure Change Log

This change log lists changes to VoteSecure with each released version. It is not comprehensive (i.e., it does not include non-material changes like fixes for typographical errors, updates to the continuous integration scripts, etc.).

## [Version 1.1.1](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_1_1) - TBD April 2026

- updated threat model and procedures to address security advisories [GHSA-v43c-fm6q-w8f8](https://github.com/FreeAndFair/VoteSecure/security/advisories/GHSA-v43c-fm6q-w8f8) and [GHSA-w7jj-jfcc-gf89](https://github.com/FreeAndFair/VoteSecure/security/advisories/GHSA-w7jj-jfcc-gf89)
- removed the Cryptol compiler and all references thereto, as we were not actually using it to generate code
- fixed a minor type inference issue that prevented the Cryptol model from working with current versions of Cryptol
- added continuous integration for the Isabelle E2E-VIV session
- reimplemented the browsable view of the threat model as a completely local HTML/JavaScript document with additional views, cross-linking, and many other quality-of-life enhancements; this is now part of each release, in addition to the PDF version of the threat model ([direct download link](https://github.com/FreeAndFair/TuskMobileVoting/releases/download/latest/threat-model.html))

## [Version 1.1](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_1) - 6 February 2026

- implemented mitigations for [a reported clash attack](https://github.com/FreeAndFair/VoteSecure/issues/6), which was originally reported as a security advisory; the implemented mitigations are described in the issue
- updated the protocol descriptions and diagrams to include the implemented mitigations
- updated the threat model to include the reported clash attack and its mitigations, and did some additional threat model cleanup
- implemented a missing check for a matching ballot tracker within the voting application's check procedure
- modified cryptographic context function names and usage for clarity
- reimplemented the threat model in Python and provided an additional graph visualization for it

## [Version 1.0 (with Updated Documentation)](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_0_updated_docs) - 20 November 2025

- brought documentation, specifications, and diagrams up-to-date with the code in the initial release

## [Version 1.0](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_0) - 14 November 2025

- initial release
