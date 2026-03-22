#!/bin/bash
#
# This script needs to be run with root privilege
#

TARGET_PLATFORM="oldgrub"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

call_oracle \
	--input secret \
	--output sealed \
	--from current \
	seal-secret $PCR_MASK

echo "attempt to unseal the secret"
call_oracle \
	--input sealed \
	--output recovered \
	unseal-secret $PCR_MASK

if ! cmp secret recovered; then
	echo "BAD: Unable to recover original secret"
	echo "Secret:"
	od -tx1c secret
	echo "Recovered:"
	od -tx1c recovered
	exit 1
else
	echo "NICE: we were able to recover the original secret"
fi

echo "Extend PCR 12. Unsealing should fail afterwards"
tpm2_pcrextend 12:sha256=21d2013e3081f1e455fdd5ba6230a8620c3cfc9a9c31981d857fe3891f79449e
rm -f recovered
call_oracle \
	--input sealed \
	--output recovered \
	unseal-secret $PCR_MASK || true

if [ -s recovered ] && ! cmp secret recovered; then
	echo "BAD: We were still able to recover the original secret. Something stinks"
	exit 1
else
	echo "GOOD: After changing a PCR, the secret can no longer be unsealed"
fi
