# Important Files

- `src/oracle.c`: Main entry point and argument parsing for `pcr-oracle`.
- `src/tpm.c`: TPM interface implementation and testing functionality.
- `src/pcr-policy.c`: PCR policy generation and handling routines.
- `src/key.c`: Generic asymmetric key handling (formerly `rsa.c`), supporting RSA and ECC.
- `src/key.h`: Header for generic key operations.
- `tests/common.sh`: Common testing boilerplate (like starting `swtpm`) shared across integration tests.
- `tests/test-*.sh`: Independent integration tests, verifying behaviors across different target platforms.
