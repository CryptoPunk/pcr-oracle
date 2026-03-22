#!/bin/bash
#
# This script needs to be run with root privilege
#

TARGET_PLATFORM="tpm2.0"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

echo "Seal the secret with PCR policy"
call_oracle \
	--from current \
	--input secret \
	--output sealed \
	--srk-algorithm=ecc \
	seal-secret $PCR_MASK

echo "Unseal the sealed with PCR policy"
call_oracle \
	--input sealed \
	--output recovered \
	unseal-secret

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

rm -f sealed recovered

call_oracle \
	--generate-key \
	--private-key policy-key.pem \
	--auth authorized.policy \
	create-authorized-policy $PCR_MASK

call_oracle \
	--private-key policy-key.pem \
	--public-key policy-pubkey \
	store-public-key

call_oracle \
	--auth authorized.policy \
	--input secret \
	--output sealed \
	--srk-algorithm=ecc \
	seal-secret

for attempt in first second; do
	echo "Sign the set of PCRs we want to authorize"
	call_oracle \
		--policy-name "authorized-policy-test" \
		--private-key policy-key.pem \
		--from current \
		--input sealed \
		--output sealed-signed \
		sign $PCR_MASK

	echo "$attempt attempt to unseal the secret"
	call_oracle \
		--input sealed-signed \
		--output recovered \
		unseal-secret

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

	if [ "$attempt" = "second" ]; then
		break
	fi

	echo "Extend PCR 12. Unsealing should fail afterwards"
	tpm2_pcrextend 12:sha256=21d2013e3081f1e455fdd5ba6230a8620c3cfc9a9c31981d857fe3891f79449e
	rm -f recovered
	call_oracle \
		--input sealed-signed \
		--output recovered \
		unseal-secret || true

	if [ -s recovered ] && ! cmp secret recovered; then
		echo "BAD: We were still able to recover the original secret. Something stinks"
		exit 1
	else
		echo "GOOD: After changing a PCR, the secret can no longer be unsealed"
	fi

	echo "Now recreate the signed PCR policy"
done
