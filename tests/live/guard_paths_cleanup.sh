# Sourced by the T33 recipe and its stub-Docker tests. The caller supplies live_compose_down.
# Keep cleaning after every failure, but never replace an earlier test failure with success.
cleanup_guard_paths() {
    cleanup_original_status=$1
    cleanup_failed=0
    shift
    if captures=$(docker ps -aq --filter 'name=secscan-live-t33-capture-'); then
        if [ -n "$captures" ]; then
            docker rm -f -v $captures >/dev/null || cleanup_failed=1
        fi
    else
        cleanup_failed=1
    fi
    # Includes the control-network receiver, which network-based removal below cannot find.
    if receivers=$(docker ps -aq --filter 'name=secscan-live-t11-t33-'); then
        if [ -n "$receivers" ]; then
            docker rm -f -v $receivers >/dev/null || cleanup_failed=1
        fi
    else
        cleanup_failed=1
    fi
    for net in "$@"; do
        if ids=$(docker ps -aq --filter "network=$net"); then
            if [ -n "$ids" ]; then
                docker rm -f -v $ids >/dev/null || cleanup_failed=1
            fi
        else
            cleanup_failed=1
        fi
    done
    live_compose_down || cleanup_failed=1
    for net in "$@"; do
        docker network rm "$net" >/dev/null || cleanup_failed=1
    done
    if [ "$cleanup_original_status" -ne 0 ]; then
        return "$cleanup_original_status"
    fi
    return "$cleanup_failed"
}

# Installed before the T33 stack operations (signal behavior covered by process-group tests).
guard_paths_install_cleanup() {
    guard_paths_scan_net=$1
    guard_paths_lab_net=$2
    status=${status:-0}
    trap 'guard_paths_exit "$?"' 0
    trap 'guard_paths_exit 130' INT
    trap 'guard_paths_exit 143' TERM
}

guard_paths_exit() {
    guard_paths_trigger_status=$1
    # Disable EXIT recursion and ignore repeated interrupts while cleanup is in progress.
    trap - 0
    trap '' INT TERM
    if [ "$status" -eq 0 ]; then
        status=$guard_paths_trigger_status
    fi
    cleanup_guard_paths "$status" "$guard_paths_scan_net" "$guard_paths_lab_net"
    guard_paths_final_status=$?
    exit "$guard_paths_final_status"
}
