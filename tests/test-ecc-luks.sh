#!/bin/bash
# Test sealing a 64-byte secret with ECC templates

. $(dirname "${BASH_SOURCE[0]}")/common.sh

echo "Creating 64-byte secret..."
dd if=/dev/urandom of="$TESTDIR/secret64" bs=1 count=64 2>/dev/null >/dev/null

echo "Generating ECC key..."
call_oracle --generate-key --key-algorithm ecc --private-key "$TESTDIR/ecc-key.pem" \
    --auth "$TESTDIR/policy-ecc" create-authorized-policy 0,2,4,7

echo "Attempting to seal 64-byte secret with ECC SRK..."
call_oracle --target-platform tpm2.0 --key-algorithm ecc --srk-algorithm ecc \
    --auth "$TESTDIR/policy-ecc" --input "$TESTDIR/secret64" \
    --output "$TESTDIR/sealed64" seal-secret

echo "Success!"
