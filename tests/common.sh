#!/bin/bash
# Common test functions and setup

export PCR_MASK="0,2,4,12"

# Find pcr-oracle relative to this script
PCR_ORACLE_BIN=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../pcr-oracle")

if [ ! -x "$PCR_ORACLE_BIN" ]; then
    echo "FAIL: Cannot find pcr-oracle executable at $PCR_ORACLE_BIN" >&2
    exit 1
fi

function call_oracle {
	echo "****************"
	echo "pcr-oracle $*"
	$PCR_ORACLE_BIN --target-platform "${TARGET_PLATFORM:-tpm2.0}" -d "$@"
}

if [ -z "$TESTDIR" ]; then
	tmpdir=$(mktemp -d /tmp/pcrtestXXXXXX)

	mkdir -p "$tmpdir/swtpm"
	swtpm socket --tpmstate dir="$tmpdir/swtpm" --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init,startup-clear &
	SWTPM_PID=$!
	sleep 1

	export TPM2TOOLS_TCTI="swtpm:port=2321"
	export TPM2_PKCS11_TCTI="swtpm:port=2321"
	export TPM2_ABRMD_TCTI="swtpm:port=2321"

	tpm2_startup -c

	trap "kill $SWTPM_PID 2>/dev/null; cd / && rm -rf $tmpdir" 0 1 2 10 11 15

	TESTDIR=$tmpdir
fi

trap "echo 'FAIL: command exited with error'; exit 1" ERR

echo "This is super secret" >"$TESTDIR/secret"

set -e
cd "$TESTDIR"
