#!/bin/bash
#
# This script tests authorized policies using ECC keys.
#

TARGET_PLATFORM="oldgrub"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

echo "Generate ECC key and authorized policy"
call_oracle \
	--key-algorithm ecc \
	--generate-key \
	--private-key policy-key-ecc.pem \
	--auth authorized.policy.ecc \
	create-authorized-policy $PCR_MASK

echo "Store public ECC key"
call_oracle \
	--private-key policy-key-ecc.pem \
	--public-key policy-pubkey-ecc \
	store-public-key

# Write the same public key, but as PEM file.
call_oracle \
	--private-key policy-key-ecc.pem \
	--public-key policy-pubkey-ecc.pem \
	store-public-key

# Make sure that the PEM formatted public key we extracted matches what openssl would produce
openssl pkey -in policy-key-ecc.pem -pubout -out pubkey2-ecc.pem
if ! cmp pubkey2-ecc.pem policy-pubkey-ecc.pem; then
	echo "BAD: storing the public key did not generate the same PEM file as openssl did"
	exit 1
fi
rm -f pubkey2-ecc.pem

echo "Seal secret against ECC authorized policy"
call_oracle \
	--auth authorized.policy.ecc \
	--input secret \
	--output sealed.ecc \
	seal-secret

for attempt in first second; do
	echo "Sign the set of PCRs we want to authorize (ECC)"
	call_oracle \
		--private-key policy-key-ecc.pem \
		--from current \
		--output signed.policy.ecc \
		sign $PCR_MASK

	echo "$attempt attempt to unseal the secret (ECC)"
	call_oracle \
		--input sealed.ecc \
		--output recovered.ecc \
		--public-key policy-pubkey-ecc \
		--pcr-policy signed.policy.ecc \
		unseal-secret $PCR_MASK

	if ! cmp secret recovered.ecc; then
		echo "BAD: Unable to recover original secret with ECC"
		exit 1
	else
		echo "NICE: we were able to recover the original secret with ECC"
	fi

	if [ "$attempt" = "second" ]; then
		break
	fi

	echo "Extend PCR 12. Unsealing should fail afterwards"
	tpm2_pcrextend 12:sha256=21d2013e3081f1e455fdd5ba6230a8620c3cfc9a9c31981d857fe3891f79449e
	rm -f recovered.ecc
	call_oracle \
		--input sealed.ecc \
		--output recovered.ecc \
		--public-key policy-pubkey-ecc \
		--pcr-policy signed.policy.ecc \
		unseal-secret $PCR_MASK || true

	if [ -s recovered.ecc ] && ! cmp secret recovered.ecc; then
		echo "BAD: We were still able to recover the original secret. Something stinks"
		exit 1
	else
		echo "GOOD: After changing a PCR, the secret can no longer be unsealed (ECC)"
	fi

	echo "Now recreate the signed PCR policy (ECC)"
done
