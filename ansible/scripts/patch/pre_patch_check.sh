#!/usr/bin/env bash
# =============================================================================
# pre_patch_check.sh - verify that a host is safe to patch and record its
#                      pre-patch state. Distro independent (apt and yum/dnf).
#
# Usage:
#   pre_patch_check.sh --patch-id ID --output FILE
#                      [--min-free-mb N]        free space required on / and /var (default 1024)
#                      [--min-boot-free-mb N]   free space required on /boot (default 100)
#                      [--lock-wait SECONDS]    how long to wait for a busy package manager (default 120)
#                      [--skip-repo-check]      do not test repository reachability
#                      [--snapshot-only]        only record state, run no checks
#
# Checks
#   * root privileges, writable state directory, read-only filesystems
#   * free disk space and inodes on /, /var and /boot
#   * package manager locks / running apt, dpkg, yum, dnf, rpm processes
#   * broken dpkg / rpm database state, unfinished transactions, apt-get check
#   * repository reachability (apt-get update / yum|dnf makecache)
#   * RHEL subscription, held / version-locked packages, pending reboot,
#     degraded systemd state, low memory, implausible clock
#
# State written to /var/lib/provisioner/patch/<patch_id>/ (kept if it already
# exists so that a re-run does not lose the original baseline):
#   services.before  running services     failed.before  failed units
#   kernel.before    running kernel       boot_id.before kernel boot id
#
# Output JSON: {"passed":true|false,"messages":["FAIL: ..","WARN: ..","INFO: .."],"checked_at":".."}
# "passed" is false when at least one FAIL message exists. Exit code is 0
# whenever the output file was written.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [ ! -r "$SCRIPT_DIR/patch_common.sh" ]; then
    echo "FATAL: $SCRIPT_DIR/patch_common.sh not found" >&2
    exit 3
fi
# shellcheck source=patch_common.sh
. "$SCRIPT_DIR/patch_common.sh" || { echo "FATAL: cannot load patch_common.sh" >&2; exit 3; }

MIN_FREE_MB=1024
MIN_BOOT_FREE_MB=100
LOCK_WAIT=120
SKIP_REPO_CHECK=0
SNAPSHOT_ONLY=0

MESSAGES=()
FAIL_COUNT=0
CHECK_WRITTEN=0

msg_fail() { MESSAGES[${#MESSAGES[@]}]="FAIL: $(flatten "$*")"; FAIL_COUNT=$(( FAIL_COUNT + 1 )); log "FAIL: $*"; }
msg_warn() { MESSAGES[${#MESSAGES[@]}]="WARN: $(flatten "$*")"; log "WARN: $*"; }
msg_info() { MESSAGES[${#MESSAGES[@]}]="INFO: $(flatten "$*")"; log "INFO: $*"; }

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --patch-id)          PATCH_ID="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --patch-id=*)        PATCH_ID="${1#*=}"; shift ;;
            --output)            OUTPUT_FILE="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --output=*)          OUTPUT_FILE="${1#*=}"; shift ;;
            --min-free-mb)       MIN_FREE_MB="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --min-free-mb=*)     MIN_FREE_MB="${1#*=}"; shift ;;
            --min-boot-free-mb)  MIN_BOOT_FREE_MB="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --min-boot-free-mb=*) MIN_BOOT_FREE_MB="${1#*=}"; shift ;;
            --lock-wait)         LOCK_WAIT="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --lock-wait=*)       LOCK_WAIT="${1#*=}"; shift ;;
            --skip-repo-check)   SKIP_REPO_CHECK=1; shift ;;
            --snapshot-only)     SNAPSHOT_ONLY=1; shift ;;
            -h|--help)           usage; exit 0 ;;
            *)                   msg_warn "ignored unknown argument: $1"; shift ;;
        esac
    done
    if [ -z "$OUTPUT_FILE" ]; then
        echo "FATAL: --output FILE is required" >&2
        exit 2
    fi
    MIN_FREE_MB="$(uint_or "$MIN_FREE_MB" 1024)"
    MIN_BOOT_FREE_MB="$(uint_or "$MIN_BOOT_FREE_MB" 100)"
    LOCK_WAIT="$(uint_or "$LOCK_WAIT" 120)"
}

write_check_output() {
    local tmp="${OUTPUT_FILE}.tmp.$$" passed="true"
    [ "$FAIL_COUNT" -gt 0 ] && passed="false"
    mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true
    {
        printf '{"passed":%s,"messages":' "$passed"
        if [ "${#MESSAGES[@]}" -eq 0 ]; then
            printf '[]'
        else
            printf '%s\n' "${MESSAGES[@]}" | json_lines_to_array
        fi
        printf ',"checked_at":%s}\n' "$(json_str "$(now_iso)")"
    } > "$tmp" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }
    _utf8_clean "$tmp"
    mv -f "$tmp" "$OUTPUT_FILE" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }
    chmod 0644 "$OUTPUT_FILE" 2>/dev/null || true
    CHECK_WRITTEN=1
    if [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ] && [ "$OUTPUT_FILE" != "$STATE_DIR/pre_check.json" ]; then
        cp -f "$OUTPUT_FILE" "$STATE_DIR/pre_check.json" 2>/dev/null || true
    fi
    return 0
}

on_exit() {
    local rc=$?
    if [ "$CHECK_WRITTEN" -eq 0 ] && [ -n "$OUTPUT_FILE" ]; then
        msg_fail "pre-check terminated unexpectedly (exit code $rc)"
        if write_check_output; then rc=0; else rc=3; fi
    fi
    [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR" 2>/dev/null
    exit "$rc"
}

# ----------------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------------
check_privileges() {
    if ! is_root; then
        msg_fail "pre-check is not running as root; patching requires root privileges"
    fi
    if [ -z "$PKG_FAMILY" ]; then
        msg_fail "no supported package manager found (need apt/dpkg or rpm with yum/dnf)"
    fi
    local probe="$STATE_DIR/.write_probe.$$"
    if ! ( : > "$probe" ) 2>/dev/null; then
        msg_fail "state directory $STATE_DIR is not writable"
    else
        rm -f "$probe" 2>/dev/null
    fi
}

# mount point that holds PATH
mount_of() {
    df -P "$1" 2>/dev/null | awk 'NR == 2 { m = $6; for (i = 7; i <= NF; i++) m = m " " $i; print m }'
}

check_readonly() {
    local p mp opts seen=" "
    for p in / /var /usr /boot /tmp; do
        [ -d "$p" ] || continue
        mp="$(mount_of "$p")"
        [ -n "$mp" ] || continue
        case "$seen" in *" $mp "*) continue ;; esac
        seen="$seen$mp "
        opts="$(awk -v m="$mp" '$2 == m { o = $4 } END { print o }' /proc/mounts 2>/dev/null)"
        case ",$opts," in
            *,ro,*) msg_fail "filesystem $mp is mounted read-only (remounted after I/O errors?)" ;;
        esac
    done
}

check_disk_space() {
    local p mp avail need seen=" " pct
    for p in / /var /boot; do
        [ -d "$p" ] || continue
        mp="$(mount_of "$p")"
        [ -n "$mp" ] || { msg_warn "could not determine the filesystem of $p"; continue; }
        case "$seen" in *" $mp "*) continue ;; esac
        seen="$seen$mp "
        avail="$(run_to 30 df -Pm "$p" 2>/dev/null | awk 'NR == 2 { print $(NF - 2) }')"
        if ! is_uint "$avail"; then
            msg_warn "could not read free space of $mp"
            continue
        fi
        need="$MIN_FREE_MB"
        # a dedicated /boot is small by design
        if [ "$mp" = "/boot" ] || [ "$mp" = "/boot/efi" ]; then
            need="$MIN_BOOT_FREE_MB"
        fi
        if [ "$avail" -lt "$need" ]; then
            msg_fail "$mp has ${avail} MB free, ${need} MB required"
        else
            msg_info "$mp has ${avail} MB free (minimum ${need} MB)"
        fi
        pct="$(run_to 30 df -Pi "$p" 2>/dev/null | awk 'NR == 2 { v = $(NF - 1); gsub(/%/, "", v); print v }')"
        if is_uint "$pct"; then
            if [ "$pct" -ge 98 ]; then
                msg_fail "$mp has ${pct}% of its inodes in use"
            elif [ "$pct" -ge 90 ]; then
                msg_warn "$mp has ${pct}% of its inodes in use"
            fi
        fi
    done
    # package caches living on their own filesystem
    for p in /var/cache/apt/archives /var/cache/dnf /var/cache/yum; do
        [ -d "$p" ] || continue
        mp="$(mount_of "$p")"
        case "$seen" in *" $mp "*) continue ;; esac
        seen="$seen$mp "
        avail="$(run_to 30 df -Pm "$p" 2>/dev/null | awk 'NR == 2 { print $(NF - 2) }')"
        if is_uint "$avail" && [ "$avail" -lt 512 ]; then
            msg_fail "package cache filesystem $mp has only ${avail} MB free (512 MB required)"
        fi
    done
}

check_memory() {
    [ -r /proc/meminfo ] || return 0
    local avail
    avail="$(awk '/^MemAvailable:/ { a = $2; h = 1 } /^MemFree:/ { f = $2 } /^Cached:/ { c = $2 } END { if (!h) a = f + c; printf "%d", a / 1024 }' /proc/meminfo 2>/dev/null)"
    if is_uint "$avail" && [ "$avail" -lt 200 ]; then
        msg_warn "only ${avail} MB of memory available; dnf/apt may be killed by the OOM killer"
    fi
}

check_clock() {
    local year
    year="$(date -u +%Y 2>/dev/null)"
    if is_uint "$year" && [ "$year" -lt 2024 ]; then
        msg_warn "system clock reports year $year; TLS certificate and repository signature validation will fail"
    fi
}

busy_package_manager() {
    local pids=""
    if [ "$PKG_FAMILY" = "deb" ]; then
        pids="$(pgrep -x -d ' ' 'apt|apt-get|aptitude|dpkg|unattended-upgr|apt.systemd.dai' 2>/dev/null)"
    else
        pids="$(pgrep -x -d ' ' 'yum|dnf|rpm|dnf-automatic|yum-cron' 2>/dev/null)"
        if [ -z "$pids" ] && [ -e /var/run/yum.pid ]; then
            local p
            p="$(cat /var/run/yum.pid 2>/dev/null)"
            if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
                pids="$p"
            fi
        fi
    fi
    printf '%s' "$pids"
}

check_locks() {
    local waited=0 pids
    pids="$(busy_package_manager)"
    while [ -n "$pids" ] && [ "$waited" -lt "$LOCK_WAIT" ]; do
        sleep 5
        waited=$(( waited + 5 ))
        pids="$(busy_package_manager)"
    done
    if [ -n "$pids" ]; then
        local names
        # shellcheck disable=SC2086
        names="$(ps -o comm= -p $(printf '%s' "$pids" | tr ' ' ',') 2>/dev/null | sort -u | tr '\n' ' ')"
        msg_fail "package manager is busy after waiting ${LOCK_WAIT}s (pids: $pids; ${names:-unknown})"
    elif [ "$waited" -gt 0 ]; then
        msg_info "waited ${waited}s for another package manager process to finish"
    fi
    if [ "$PKG_FAMILY" = "deb" ] && [ -e /var/lib/dpkg/lock-frontend ] && have fuser; then
        if fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock > /dev/null 2>&1; then
            msg_fail "a dpkg/apt lock file is held by another process"
        fi
    fi
}

check_deb_state() {
    local audit broken
    audit="$(run_to 60 dpkg --audit 2>/dev/null | head -n 5)"
    broken="$(run_to 60 dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' 2>/dev/null | awk '$1 !~ /^(ii|rc|hi|un|pn)$/ { printf "%s(%s) ", $2, $1 }' | cut -c1-300)"
    if [ -n "$audit" ] || [ -n "$broken" ]; then
        msg_warn "dpkg has half-installed / unconfigured packages (${broken:-see dpkg --audit}); the patch script will run 'dpkg --configure -a' first"
    fi
    if ls /var/lib/dpkg/updates/[0-9]* > /dev/null 2>&1; then
        msg_warn "an interrupted dpkg run was detected (/var/lib/dpkg/updates is not empty)"
    fi
    local out rc
    out="$(run_to 120 apt-get check -q -o Debug::NoLocking=true 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        if [ -n "$audit$broken" ]; then
            msg_warn "apt-get check reports problems, probably caused by the unconfigured packages above: $(printf '%s' "$out" | grep -E '^E:' | head -n 2 | tr '\n' ' ')"
        else
            msg_fail "apt-get check reports broken dependencies: $(printf '%s' "$out" | grep -E '^E:' | head -n 2 | tr '\n' ' ')"
        fi
    fi
    local held
    held="$(apt-mark showhold 2>/dev/null | tr '\n' ' ')"
    if [ -n "${held// /}" ]; then
        msg_info "packages on hold will not be updated: $held"
    fi
}

check_rpm_state() {
    if ! run_to 120 rpm -q rpm > /dev/null 2>&1; then
        msg_fail "rpm database is not usable ('rpm -q rpm' failed); rebuild it with 'rpm --rebuilddb'"
        return 0
    fi
    if ls /var/lib/yum/transaction-all* > /dev/null 2>&1; then
        msg_warn "an unfinished yum transaction exists (/var/lib/yum/transaction-all*); the patch script will try yum-complete-transaction --cleanup-only"
    fi
    if have package-cleanup; then
        local dupes
        dupes="$(run_to 180 package-cleanup --dupes -q 2>/dev/null | head -n 6 | tr '\n' ' ')"
        if [ -n "${dupes// /}" ]; then
            msg_fail "duplicate packages in the rpm database (interrupted transaction): $dupes"
        fi
    elif have dnf; then
        local dupes
        dupes="$(run_to 180 dnf -q repoquery --duplicates 2>/dev/null | grep -vE '^(kernel|kernel-core|kernel-modules|kernel-modules-core|kernel-modules-extra|kernel-devel|kernel-uek|kernel-uek-core|kernel-uek-modules|installonlypkg)' | head -n 6 | tr '\n' ' ')"
        if [ -n "${dupes// /}" ]; then
            msg_fail "duplicate packages in the rpm database (interrupted transaction): $dupes"
        fi
    fi
    local locks=""
    if have dnf; then
        locks="$(run_to 60 dnf -q versionlock list 2>/dev/null | grep -vcE '^(Last metadata|$)')"
    elif have yum; then
        locks="$(run_to 60 yum -q versionlock list 2>/dev/null | grep -cE '^[0-9]+:')"
    fi
    if is_uint "$locks" && [ "$locks" -gt 0 ]; then
        msg_info "$locks version-locked package(s) will not be updated"
    fi
}

check_rhel_subscription() {
    [ "$OS_ID" = "rhel" ] || return 0
    have subscription-manager || return 0
    local out rc
    out="$(run_to 120 subscription-manager identity 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
        if ls /etc/yum.repos.d/*rhui* > /dev/null 2>&1 || grep -lsqE 'rhui' /etc/yum.repos.d/*.repo 2>/dev/null; then
            msg_info "host is not registered with subscription-manager; RHUI repositories are used"
        else
            msg_warn "RHEL host is not registered with subscription-manager: $(flatten "${out:0:120}")"
        fi
    fi
}

check_repos_deb() {
    local out="$WORK_DIR/apt_update.out" rc
    run_to "$PM_TIMEOUT" apt-get update -q -o DPkg::Lock::Timeout=60 -o Acquire::Retries=2 > "$out" 2>&1
    rc=$?
    local errs ok
    errs="$(grep -cE '^(Err:|W: Failed to fetch|E: Failed to fetch)' "$out" 2>/dev/null)"
    ok="$(grep -cE '^(Hit:|Get:|Ign:)' "$out" 2>/dev/null)"
    errs="$(uint_or "$errs" 0)"
    ok="$(uint_or "$ok" 0)"
    if [ "$rc" -eq 124 ]; then
        msg_fail "apt-get update timed out after ${PM_TIMEOUT}s; repositories are not reachable"
    elif [ "$rc" -ne 0 ]; then
        msg_fail "apt-get update failed (rc=$rc): $(grep -E '^(E:|Err:)' "$out" | head -n 2 | tr '\n' ' ')"
    elif [ "$errs" -gt 0 ] && [ "$ok" -eq 0 ]; then
        msg_fail "no APT repository could be reached: $(grep -E '^(Err:|W: Failed)' "$out" | head -n 2 | tr '\n' ' ')"
    elif [ "$errs" -gt 0 ]; then
        msg_warn "$errs APT source(s) could not be refreshed: $(grep -E '^(Err:|W: Failed)' "$out" | head -n 2 | tr '\n' ' ')"
    else
        msg_info "APT repositories reachable"
    fi
    if grep -qE '(NO_PUBKEY|EXPKEYSIG|is not signed|KEYEXPIRED)' "$out" 2>/dev/null; then
        msg_warn "repository signature problems: $(grep -E '(NO_PUBKEY|EXPKEYSIG|is not signed|KEYEXPIRED)' "$out" | head -n 2 | tr '\n' ' ')"
    fi
}

check_repos_rpm() {
    local pm out="$WORK_DIR/makecache.out" rc n
    if have dnf; then pm="dnf"; elif have yum; then pm="yum"; else msg_fail "neither dnf nor yum found"; return 0; fi
    if [ "$pm" = "dnf" ]; then
        run_to "$PM_TIMEOUT" dnf -q makecache --refresh > "$out" 2>&1
        rc=$?
    else
        run_to "$PM_TIMEOUT" yum -q clean expire-cache > /dev/null 2>&1
        run_to "$PM_TIMEOUT" yum -q makecache fast > "$out" 2>&1
        rc=$?
        if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
            run_to "$PM_TIMEOUT" yum -q makecache > "$out" 2>&1
            rc=$?
        fi
    fi
    if [ "$rc" -eq 124 ]; then
        msg_fail "$pm makecache timed out after ${PM_TIMEOUT}s; repositories are not reachable"
    elif [ "$rc" -ne 0 ]; then
        local why
        why="$(grep -vE '^[[:space:]]*$' "$out" | tail -n 3 | tr '\n' ' ' | cut -c1-400)"
        msg_fail "$pm makecache failed (rc=$rc): $why"
        if grep -q 'mirrorlist.centos.org' "$out" 2>/dev/null; then
            msg_fail "repositories still use the retired mirrorlist.centos.org; switch them to vault.centos.org or an extended-support mirror"
        fi
    else
        n="$(run_to "$PM_TIMEOUT" "$pm" -q repolist enabled 2>/dev/null | awk 'NR > 1 && NF > 0 && $1 !~ /^(repolist:|Loaded|Loading|\*)/ { n++ } END { print n + 0 }')"
        if [ "$(uint_or "$n" 0)" -eq 0 ]; then
            msg_fail "no enabled package repositories"
        else
            msg_info "$n package repositor(y/ies) reachable"
        fi
    fi
}

check_pending_reboot() {
    local pending=0
    if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then
        pending=1
    elif have needs-restarting; then
        run_to 120 needs-restarting -r > /dev/null 2>&1
        [ $? -eq 1 ] && pending=1
    fi
    if [ "$pending" -eq 1 ]; then
        msg_warn "a reboot is already pending from earlier updates; services may still run old code after this patch run"
    fi
}

check_systemd_state() {
    have systemctl || return 0
    [ -d /run/systemd/system ] || return 0
    local st
    st="$(run_to 30 systemctl is-system-running 2>/dev/null)"
    case "$st" in
        running|"") ;;
        degraded)
            msg_warn "systemd state is 'degraded' before patching; failed units: $(tr '\n' ' ' < "$STATE_DIR/failed.before" 2>/dev/null | cut -c1-300)" ;;
        starting|initializing)
            msg_warn "system is still booting (systemd state '$st')" ;;
        maintenance|stopping)
            msg_fail "systemd state is '$st'; the host is not in normal operation" ;;
        *)  msg_info "systemd state: $st" ;;
    esac
}

# ----------------------------------------------------------------------------
# State snapshot
# ----------------------------------------------------------------------------
write_if_missing() {
    # write_if_missing FILE  (content on stdin)
    local f="$1"
    if [ -s "$f" ] || [ -e "$f.done" ]; then
        cat > /dev/null
        return 0
    fi
    cat > "$f" 2>/dev/null
    : > "$f.done" 2>/dev/null
}

snapshot_state() {
    if have systemctl && [ -d /run/systemd/system ]; then
        run_to 60 systemctl list-units --type=service --state=running --no-legend --plain --no-pager 2>/dev/null \
            | awk '{ u = $1; if (u !~ /\./ && NF > 1) u = $2; if (u ~ /\.service$/) print u }' | sort -u \
            | write_if_missing "$STATE_DIR/services.before"
        run_to 60 systemctl list-units --state=failed --no-legend --plain --no-pager 2>/dev/null \
            | awk '{ u = $1; if (u !~ /\./ && NF > 1) u = $2; if (u ~ /\./) print u }' | sort -u \
            | write_if_missing "$STATE_DIR/failed.before"
    else
        msg_info "systemd is not running as init; no service snapshot taken"
        : | write_if_missing "$STATE_DIR/services.before"
        : | write_if_missing "$STATE_DIR/failed.before"
    fi
    uname -r | write_if_missing "$STATE_DIR/kernel.before"
    cat /proc/sys/kernel/random/boot_id 2>/dev/null | write_if_missing "$STATE_DIR/boot_id.before"
    local n
    n="$(wc -l < "$STATE_DIR/services.before" 2>/dev/null | tr -d ' ')"
    msg_info "state snapshot: $(uint_or "$n" 0) running service(s), kernel $(uname -r)"
}

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
main() {
    parse_args "$@"
    trap 'on_exit' EXIT
    trap 'msg_fail "pre-check interrupted by signal"; exit 0' TERM INT HUP

    patch_state_init
    LOG_FILE="$STATE_DIR/pre_check.log"
    : >> "$LOG_FILE" 2>/dev/null || LOG_FILE="/dev/null"
    detect_os

    if [ -z "$PATCH_ID" ] || ! [[ "$PATCH_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        msg_fail "missing or invalid --patch-id '$PATCH_ID'"
    fi

    snapshot_state

    if [ "$SNAPSHOT_ONLY" -eq 1 ]; then
        msg_info "pre-checks skipped on request (snapshot only)"
        write_check_output || { echo "FATAL: cannot write $OUTPUT_FILE" >&2; exit 3; }
        exit 0
    fi

    check_privileges
    check_readonly
    check_disk_space
    check_memory
    check_clock
    check_systemd_state
    check_pending_reboot

    if [ -n "$PKG_FAMILY" ]; then
        check_locks
        if [ "$PKG_FAMILY" = "deb" ]; then
            check_deb_state
        else
            check_rpm_state
            check_rhel_subscription
        fi
        if [ "$SKIP_REPO_CHECK" -eq 1 ]; then
            msg_info "repository reachability check skipped on request"
        elif [ "$FAIL_COUNT" -gt 0 ] && [ -n "$(busy_package_manager)" ]; then
            msg_info "repository check skipped because the package manager is busy"
        elif [ "$PKG_FAMILY" = "deb" ]; then
            check_repos_deb
        else
            check_repos_rpm
        fi
    fi

    if [ "$FAIL_COUNT" -eq 0 ]; then
        log "pre-check passed"
    else
        log "pre-check failed with $FAIL_COUNT blocking problem(s)"
    fi
    write_check_output || { echo "FATAL: cannot write $OUTPUT_FILE" >&2; exit 3; }
    exit 0
}

main "$@"
