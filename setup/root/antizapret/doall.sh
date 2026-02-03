#!/bin/bash
set -e

SECONDS=0

cd /root/antizapret

SUM1="$(sha256sum update.sh)"
cat update.sh | bash -s "$1"
SUM2="$(sha256sum update.sh)"
if [[ "$SUM1" != "$SUM2" ]]; then
	echo 'Restarting update.sh'
	cat update.sh | bash -s "$1"
fi
./parse.sh "$1"

echo "Execution time: $SECONDS seconds"
exit 0
