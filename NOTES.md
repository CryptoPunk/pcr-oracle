# Developer Notes

## Transition to `--srk-algorithm`
- The `--ecc-srk` option in `pcr-oracle` was replaced with `--srk-algorithm=(ecc|rsa)` for more neutral handling of symmetric/asymmetric algorithms.

## Testing with swtpm
- The test scripts (`test-*.sh`) historically required root because they attempted to access the host TPM (`/dev/tpmrm0`).
- To make testing safer and allow it to run in isolated environments (like Podman), we've updated all test scripts to spin up a local TCP `swtpm` instance on ports 2321/2322.
- Due to how `pcr-oracle` (via `tss2-tctildr`) and `tpm2-tools` connect, the test wraps standard TCTI environment variable `TPM2TOOLS_TCTI="swtpm:port=2321"` and ensures `tpm2_startup` runs correctly. `pcr-oracle` intelligently falls back to TCP localhost:2321 when device instances are unavailable.

## Refactoring Tests
- All shell tests have been moved to the `tests/` directory to clean up the project root.
- The `swtpm` spawning and other boilerplate were coalesced into `tests/common.sh`.
- Each individual test script uses `TARGET_PLATFORM` parameters before sourcing the common configuration, keeping the tests DRY.
