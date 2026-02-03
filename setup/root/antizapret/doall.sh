#!/bin/bash
set -e

SECONDS=0

cd /root/antizapret

/bin/bash update.sh "$1"
/bin/bash parse.sh "$1"

echo "Execution time: $SECONDS seconds"
exit 0