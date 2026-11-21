#!/bin/sh
# T23b-b2 (D21): entrypoint wrapper for the development db. compose runs it as
# ["/bin/sh", "/usr/local/lib/secscan/db-entrypoint.sh"], so it needs no execute bit.
# It does exactly three things and then hands over to the official entrypoint:
#   1. refuse to start when PGDATA is empty;
#   2. when the official entrypoint is about to initialise (the same test it uses:
#      $PGDATA/PG_VERSION missing or empty), create the initialisation-incomplete marker and
#      flush it to disk first, so the marker exists before anything is written to PGDATA;
#   3. exec the official entrypoint with the original arguments (PID 1 ends up as the postmaster).
# It never removes the marker (only initdb/99-end.sh does, after every init step succeeded), reads
# no secret and never changes user. With an existing PG_VERSION it does nothing.
# No `set`: every failure is handled explicitly and ends with exit 1.
secscan_initdb_marker=/var/lib/postgresql/secscan-initdb-incomplete
if [ -z "$PGDATA" ]; then
	echo "secscan db-entrypoint: PGDATA is empty; refusing to start" >&2
	exit 1
fi
if [ ! -s "$PGDATA/PG_VERSION" ]; then
	if ! printf '' > "$secscan_initdb_marker"; then
		echo "secscan db-entrypoint: cannot create the initialisation marker; refusing to start" >&2
		exit 1
	fi
	if ! sync "$secscan_initdb_marker" /var/lib/postgresql; then
		echo "secscan db-entrypoint: cannot flush the initialisation marker to disk; refusing to start" >&2
		exit 1
	fi
	echo "secscan db-entrypoint: first initialisation, marker created"
fi
exec /usr/local/bin/docker-entrypoint.sh "$@"
