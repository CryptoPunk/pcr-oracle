#!/bin/bash
#
# This script needs to be run with root privilege
#

TARGET_PLATFORM="systemd"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

POLICY_FILE=authorized.policy
SIGNED_POLICY_FILE=systemd-policy.json
rm -f sealed recovered

call_oracle \
	--rsa-generate-key \
	--private-key policy-key.pem \
	--auth $POLICY_FILE \
	create-authorized-policy $PCR_MASK

call_oracle \
	--private-key policy-key.pem \
	--public-key policy-pubkey \
	store-public-key

call_oracle \
	--auth $POLICY_FILE \
	--input secret \
	--output sealed \
	seal-secret

for attempt in first second; do
	echo "Sign the set of PCRs we want to authorize"
	call_oracle \
		--policy-name "authorized-policy-test" \
		--private-key policy-key.pem \
		--from current \
		--output $SIGNED_POLICY_FILE \
		sign $PCR_MASK

	echo "*** Contents of $SIGNED_POLICY_FILE"
	cat $SIGNED_POLICY_FILE
	echo

	echo "*** Terminating test early; the systemd code does not support unsealing yet" >&2
	break;
done
