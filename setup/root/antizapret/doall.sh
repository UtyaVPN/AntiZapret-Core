#!/bin/bash
set -e
cd /root/antizapret
/bin/bash update.sh "$1"
/bin/bash parse.sh "$1"
exit 0