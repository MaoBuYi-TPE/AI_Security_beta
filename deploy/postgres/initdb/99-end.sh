#!/bin/sh
# T23b-b2 (D18): the last init step. The entrypoint stops at the first failing init file, so this
# runs only when every earlier file succeeded; removing the marker is the success signal.
# No `set`: the entrypoint sources this file when it is not executable.
secscan_initdb_marker=/var/lib/postgresql/secscan-initdb-incomplete
rm -f -- "$secscan_initdb_marker" || exit 1
echo "secscan initdb: completed (marker removed)"
