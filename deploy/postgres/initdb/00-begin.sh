#!/bin/sh
# T23b-b2 (D18, D21): the first init step. The entrypoint wrapper
# (/usr/local/lib/secscan/db-entrypoint.sh) creates the initialisation-incomplete marker before the
# official entrypoint writes anything to PGDATA; this step only checks that the marker is there.
# A missing marker means the wrapper did not run (for example the entrypoint override was
# removed): create the marker and fail, so the database is never initialised without that
# protection and stays unhealthy afterwards (fail closed). Only 99-end.sh removes the marker.
# No `set`: the entrypoint sources this file when it is not executable.
secscan_initdb_marker=/var/lib/postgresql/secscan-initdb-incomplete
if [ -e "$secscan_initdb_marker" ]; then
	echo "secscan initdb: started (marker present)"
else
	printf '' > "$secscan_initdb_marker"
	echo "secscan initdb: the initialisation marker is missing (entrypoint wrapper not run); refusing to initialise" >&2
	exit 1
fi
