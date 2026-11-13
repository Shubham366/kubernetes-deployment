#!/usr/bin/env bash
# =============================================================================
# post_patch_check.sh - verify a host after patching (and after the optional
#                       reboot). Distro independent (apt and yum/dnf).
#
# Usage:
#   post_patch_check.sh --patch-id ID --output FILE
#                       [--services "a b"]   systemd units that MUST be active
#                       [--rebooted]         the host was rebooted by the playbook
#                       [--dry-run]          nothing was changed; skip package diff
#                       [--settle SECONDS]   max time to wait for boot/services (default 180)
#
# Checks (compared with the state recorded by pre_patch_check.sh in
# /var/lib/provisioner/patch/<patch_id>/)
#   * systemd finished booting, overall system state
#   * required services (--services) are active                     -> FAIL
#   * services that ran before patching: now failed                 -> FAIL
#                                        now stopped / missing      -> WARN
#   * failed units that were not failed before                      -> FAIL
#   * kernel: running vs. pre-patch vs. newest installed; pending reboot
#   * package database consistency (dpkg --audit / rpm)
#   * packages.after snapshot and packages.diff (name, from, to)
#   * free disk space, default route
#
# Output JSON:
#   {"passed":true|false,"messages":["FAIL: ..","WARN: ..","INFO: .."],
#    "reboot_required":true|false,"kernel_before":"..","kernel_running":"..",
#    "packages_changed":N,"checked_at":".."}
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

REQUIRED_SERVICES=""
REBOOTED=0
SETTLE=180

MESSAGES=()
FAIL_COUNT=0
CHECK_WRITTEN=0
KERNEL_BEFORE=""
KERNEL_RUNNING=""
PACKAGES_CHANGED=0
POST_REBOOT_REQUIRED="false"

# Units that come and go on their own; their absence after patching is normal.
TRANSIENT_RE='^(user@|user-runtime-dir@|session-|systemd-(hostnamed|timedated|localed|coredump@|fsck@|udev-settle|tmpfiles|ask-password|networkd-wait-online|user-sessions)|packagekit|fwupd|getty@|serial-getty@|sshd@|ssh@|apt-|dnf-|yum-|unattended-upgrades|needrestart|cloud-(init|config|final)|motd-news|man-db|logrotate|sysstat|plymouth|dracut|setroubleshootd|run-|snapd\.(seeded|autoimport)|ua-|esm-cache|geoclue|upower|udisks2|colord|bolt|rtkit|polkit|realmd|sssd-kcm|dbus-:|nm-|NetworkManager-dispatcher|systemd-rfkill|kpatch|tuned-ppd)'

msg_fail() { MESSAGES[${#MESSAGES[@]}]="FAIL: $(flatten "$*")"; FAIL_COUNT=$(( FAIL_COUNT + 1 )); log "FAIL: $*"; }
msg_warn() { MESSAGES[${#MESSAGES[@]}]="WARN: $(flatten "$*")"; log "WARN: $*"; }
msg_info() { MESSAGES[${#MESSAGES[@]}]="INFO: $(flatten "$*")"; log "INFO: $*"; }

usage() {
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --patch-id)    PATCH_ID="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --patch-id=*)  PATCH_ID="${1#*=}"; shift ;;
            --output)      OUTPUT_FILE="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --output=*)    OUTPUT_FILE="${1#*=}"; shift ;;
            --services)    REQUIRED_SERVICES="$(_split_list "${2-}")"; shift; [ $# -gt 0 ] && shift ;;
            --services=*)  REQUIRED_SERVICES="$(_split_list "${1#*=}")"; shift ;;
            --settle)      SETTLE="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --settle=*)    SETTLE="${1#*=}"; shift ;;
            --rebooted)    REBOOTED=1; shift ;;
            --dry-run)     DRY_RUN=1; shift ;;
            -h|--help)     usage; exit 0 ;;
            *)             msg_warn "ignored unknown argument: $1"; shift ;;
        esac
    done
    if [ -z "$OUTPUT_FILE" ]; then
        echo "FATAL: --output FILE is required" >&2
        exit 2
    fi
    SETTLE="$(uint_or "$SETTLE" 180)"
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
        printf ',"reboot_required":%s' "$(json_bool "$POST_REBOOT_REQUIRED")"
        printf ',"kernel_before":%s' "$(json_str "$KERNEL_BEFORE")"
        printf ',"kernel_running":%s' "$(json_str "$KERNEL_RUNNING")"
        printf ',"packages_changed":%s' "$(uint_or "$PACKAGES_CHANGED" 0)"
        printf ',"checked_at":%s}\n' "$(json_str "$(now_iso)")"
    } > "$tmp" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }
    _utf8_clean "$tmp"
    mv -f "$tmp" "$OUTPUT_FILE" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }
    chmod 0644 "$OUTPUT_FILE" 2>/dev/null || true
    CHECK_WRITTEN=1
    if [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ] && [ "$OUTPUT_FILE" != "$STATE_DIR/post_check.json" ]; then
        cp -f "$OUTPUT_FILE" "$STATE_DIR/post_check.json" 2>/dev/null || true
    fi
    return 0
}

on_exit() {
    local rc=$?
    if [ "$CHECK_WRITTEN" -eq 0 ] && [ -n "$OUTPUT_FILE" ]; then
        msg_fail "post-check terminated unexpectedly (exit code $rc)"
        if write_check_output; then rc=0; else rc=3; fi
    fi
    [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR" 2>/dev/null
    exit "$rc"
}

have_systemd() {
    have systemctl && [ -d /run/systemd/system ]
}

# ----------------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------------
wait_for_boot() {
    have_systemd || return 0
    local waited=0 st
    while :; do
        st="$(run_to 30 systemctl is-system-running 2>/dev/null)"
        case "$st" in
            starting|initializing) ;;
            *) break ;;
        esac
        if [ "$waited" -ge "$SETTLE" ]; then
            msg_warn "systemd is still '$st' ${SETTLE}s after the check started; pending jobs: $(run_to 20 systemctl list-jobs --no-legend --no-pager 2>/dev/null | awk '{ printf "%s ", $2 }' | cut -c1-200)"
            break
        fi
        sleep 5
        waited=$(( waited + 5 ))
    done
    case "$st" in
        running)     msg_info "systemd state: running" ;;
        degraded)    msg_info "systemd state: degraded (failed units are evaluated individually)" ;;
        maintenance) msg_fail "system is in maintenance (rescue/emergency) mode" ;;
        stopping)    msg_fail "system is shutting down" ;;
        "")          msg_warn "could not query the systemd state" ;;
        starting|initializing) ;;
        *)           msg_info "systemd state: $st" ;;
    esac
}

unit_exists() {
    local ls
    ls="$(systemctl show -p LoadState "$1" 2>/dev/null | awk -F= '{ print $2 }')"
    [ -n "$ls" ] && [ "$ls" != "not-found" ]
}

# wait up to N seconds for a unit to become active
wait_active() {
    local unit="$1" max="$2" waited=0 st
    while :; do
        st="$(systemctl is-active "$unit" 2>/dev/null)"
        case "$st" in
            active) return 0 ;;
            activating|reloading) ;;
            *) [ "$waited" -ge 10 ] && return 1 ;;   # give failed/inactive units a short grace period only
        esac
        [ "$waited" -ge "$max" ] && return 1
        sleep 5
        waited=$(( waited + 5 ))
    done
}

check_required_services() {
    [ -n "$REQUIRED_SERVICES" ] || return 0
    if ! have_systemd; then
        msg_warn "systemd is not available; cannot verify required services: $REQUIRED_SERVICES"
        return 0
    fi
    local u unit st
    for u in $REQUIRED_SERVICES; do
        unit="$u"
        case "$unit" in *.*) ;; *) unit="$unit.service" ;; esac
        if ! unit_exists "$unit"; then
            msg_fail "required service $unit does not exist on this host"
            continue
        fi
        if wait_active "$unit" "$SETTLE"; then
            msg_info "required service $unit is active"
        else
            st="$(systemctl is-active "$unit" 2>/dev/null)"
            msg_fail "required service $unit is '${st:-unknown}' after patching: $(systemctl status "$unit" --no-pager -n 3 2>/dev/null | tail -n 3 | tr '\n' ' ' | cut -c1-300)"
        fi
    done
}

check_previous_services() {
    have_systemd || return 0
    local before="$STATE_DIR/services.before"
    if [ ! -e "$before" ]; then
        msg_warn "no pre-patch service snapshot ($before); cannot compare running services"
        return 0
    fi
    local u st n_failed=0 n_stopped=0 stopped="" checked=0
    while IFS= read -r u; do
        [ -n "$u" ] || continue
        if [[ "$u" =~ $TRANSIENT_RE ]]; then
            continue
        fi
        checked=$(( checked + 1 ))
        st="$(systemctl is-active "$u" 2>/dev/null)"
        case "$st" in
            active|reloading) continue ;;
            activating)
                if wait_active "$u" 60; then continue; fi
                st="$(systemctl is-active "$u" 2>/dev/null)"
                ;;
        esac
        if [ "$st" = "failed" ]; then
            n_failed=$(( n_failed + 1 ))
            msg_fail "service $u was running before patching and is now failed: $(systemctl status "$u" --no-pager -n 2 2>/dev/null | tail -n 2 | tr '\n' ' ' | cut -c1-250)"
        elif ! unit_exists "$u"; then
            msg_warn "service $u was running before patching and no longer exists (package removed or renamed)"
        else
            n_stopped=$(( n_stopped + 1 ))
            stopped="$stopped $u"
        fi
    done < "$before"
    if [ "$n_stopped" -gt 0 ]; then
        msg_warn "$n_stopped service(s) that ran before patching are not active now:$(printf '%s' "$stopped" | cut -c1-400)"
    fi
    if [ "$n_failed" -eq 0 ] && [ "$n_stopped" -eq 0 ]; then
        msg_info "all $checked previously running services are active"
    fi
}

check_failed_units() {
    have_systemd || return 0
    local now="$WORK_DIR/failed.now" before="$STATE_DIR/failed.before"
    run_to 60 systemctl list-units --state=failed --no-legend --plain --no-pager 2>/dev/null \
        | awk '{ u = $1; if (u !~ /\./ && NF > 1) u = $2; if (u ~ /\./) print u }' | sort -u > "$now"
    cp -f "$now" "$STATE_DIR/failed.after" 2>/dev/null || true
    [ -s "$now" ] || return 0
    local u new="" old=""
    while IFS= read -r u; do
        [ -n "$u" ] || continue
        if [ -e "$before" ] && grep -qxF -- "$u" "$before" 2>/dev/null; then
            old="$old $u"
        else
            new="$new $u"
        fi
    done < "$now"
    if [ -n "$new" ]; then
        # services already reported individually are not repeated as failures
        local u2 fresh=""
        for u2 in $new; do
            if [ -e "$STATE_DIR/services.before" ] && grep -qxF -- "$u2" "$STATE_DIR/services.before" 2>/dev/null && ! [[ "$u2" =~ $TRANSIENT_RE ]]; then
                continue
            fi
            fresh="$fresh $u2"
        done
        if [ -n "$fresh" ]; then
            msg_fail "unit(s) failed after patching that were not failed before:$fresh"
        fi
    fi
    if [ -n "$old" ]; then
        msg_info "unit(s) failed before patching and still failed:$old"
    fi
}

newest_installed_kernel() {
    local running="$1" newest=""
    if [ "$PKG_FAMILY" = "deb" ]; then
        local flavour="${running##*-}"
        newest="$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-[0-9]*' 'linux-image-unsigned-[0-9]*' 2>/dev/null \
            | awk '$1 == "ii" { print $2 }' | sed -e 's/^linux-image-unsigned-//' -e 's/^linux-image-//' \
            | grep -E -- "-${flavour}\$" | sort -V | tail -n1)"
    elif [ "$PKG_FAMILY" = "rpm" ]; then
        local pkgs
        case "$running" in
            *uek*) pkgs="kernel-uek kernel-uek-core" ;;
            *)     pkgs="kernel kernel-core" ;;
        esac
        # shellcheck disable=SC2086
        newest="$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' $pkgs 2>/dev/null | grep -v 'is not installed' | sort -V | tail -n1)"
    fi
    printf '%s' "$newest"
}

reboot_pending_now() {
    if [ "$PKG_FAMILY" = "deb" ]; then
        [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]
        return $?
    fi
    if have needs-restarting; then
        run_to 120 needs-restarting -r > /dev/null 2>&1
        [ $? -eq 1 ]
        return $?
    fi
    if have dnf && run_to 60 dnf -q needs-restarting --help > /dev/null 2>&1; then
        run_to 120 dnf -q needs-restarting -r > /dev/null 2>&1
        [ $? -eq 1 ]
        return $?
    fi
    local newest
    newest="$(newest_installed_kernel "$(uname -r)")"
    [ -n "$newest" ] && [ "$newest" != "$(uname -r)" ]
}

check_kernel() {
    KERNEL_RUNNING="$(uname -r)"
    KERNEL_BEFORE="$(cat "$STATE_DIR/kernel.before" 2>/dev/null)"
    local newest
    newest="$(newest_installed_kernel "$KERNEL_RUNNING")"

    if is_container; then
        msg_info "container: kernel $KERNEL_RUNNING is provided by the host"
        POST_REBOOT_REQUIRED="false"
        return 0
    fi

    if [ -n "$KERNEL_BEFORE" ] && [ "$KERNEL_BEFORE" != "$KERNEL_RUNNING" ]; then
        msg_info "kernel changed from $KERNEL_BEFORE to $KERNEL_RUNNING"
    else
        msg_info "running kernel: $KERNEL_RUNNING"
    fi

    if reboot_pending_now; then
        POST_REBOOT_REQUIRED="true"
    else
        POST_REBOOT_REQUIRED="false"
    fi

    if [ "$REBOOTED" -eq 1 ]; then
        local bid_before bid_now
        bid_before="$(cat "$STATE_DIR/boot_id.before" 2>/dev/null)"
        bid_now="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
        if [ -n "$bid_before" ] && [ "$bid_before" = "$bid_now" ]; then
            msg_fail "the host was supposed to be rebooted but the boot id did not change"
        fi
        if [ -n "$newest" ] && [ "$newest" != "$KERNEL_RUNNING" ]; then
            msg_warn "booted kernel $KERNEL_RUNNING is not the newest installed kernel $newest (GRUB default entry or pinned kernel?)"
        fi
        if [ "$POST_REBOOT_REQUIRED" = "true" ]; then
            msg_warn "a reboot is still reported as required after rebooting"
        fi
    else
        if [ "$POST_REBOOT_REQUIRED" = "true" ]; then
            if [ -n "$newest" ] && [ "$newest" != "$KERNEL_RUNNING" ]; then
                msg_info "reboot pending: kernel $newest is installed, $KERNEL_RUNNING is running"
            else
                msg_info "reboot pending to activate updated core libraries / services"
            fi
        fi
    fi
}

check_package_db() {
    if [ "$PKG_FAMILY" = "deb" ]; then
        local broken
        broken="$(run_to 60 dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' 2>/dev/null | awk '$1 !~ /^(ii|rc|hi|un|pn)$/ { printf "%s(%s) ", $2, $1 }' | cut -c1-300)"
        if [ -n "$broken" ] || [ -n "$(run_to 60 dpkg --audit 2>/dev/null | head -n 1)" ]; then
            msg_fail "dpkg has half-installed / unconfigured packages after patching: ${broken:-see dpkg --audit}"
        fi
        local held="$STATE_DIR/holds.applied"
        if [ -s "$held" ]; then
            msg_warn "temporary package holds were not released: $(tr '\n' ' ' < "$held")"
        fi
    elif [ "$PKG_FAMILY" = "rpm" ]; then
        if ! run_to 120 rpm -q rpm > /dev/null 2>&1; then
            msg_fail "rpm database is not usable after patching"
            return 0
        fi
        if ls /var/lib/yum/transaction-all* > /dev/null 2>&1; then
            msg_fail "an unfinished yum transaction was left behind (/var/lib/yum/transaction-all*)"
        fi
        if have package-cleanup; then
            local dupes
            dupes="$(run_to 180 package-cleanup --dupes -q 2>/dev/null | head -n 6 | tr '\n' ' ')"
            if [ -n "${dupes// /}" ]; then
                msg_fail "duplicate packages after patching (interrupted transaction): $dupes"
            fi
        fi
    fi
}

check_package_diff() {
    if [ "$DRY_RUN" -eq 1 ]; then
        msg_info "dry-run: no package snapshot taken"
        return 0
    fi
    local before="$STATE_DIR/packages.before" after="$STATE_DIR/packages.after" diff="$STATE_DIR/packages.diff"
    if ! snapshot_packages "$after"; then
        msg_warn "could not snapshot installed packages after patching"
        return 0
    fi
    if [ ! -s "$before" ]; then
        msg_warn "no pre-patch package snapshot ($before); cannot compute the package diff"
        return 0
    fi
    diff_packages "$before" "$after" > "$diff" 2>/dev/null
    PACKAGES_CHANGED="$(awk 'length($0) > 0 { n++ } END { print n + 0 }' "$diff" 2>/dev/null)"
    PACKAGES_CHANGED="$(uint_or "$PACKAGES_CHANGED" 0)"
    local removed
    removed="$(awk -F'\t' -v afterf="$after" '
        BEGIN { while ((getline l < afterf) > 0) { split(l, a, "\t"); names[a[1]] = 1 } close(afterf) }
        !($1 in names) { n++ } END { print n + 0 }' "$before" 2>/dev/null)"
    msg_info "$PACKAGES_CHANGED package version(s) changed, $(uint_or "$removed" 0) package(s) removed (diff: $diff)"
}

check_disk_after() {
    local p avail seen=" " mp
    for p in / /var /boot; do
        [ -d "$p" ] || continue
        mp="$(df -P "$p" 2>/dev/null | awk 'NR == 2 { print $6 }')"
        case "$seen" in *" $mp "*) continue ;; esac
        seen="$seen$mp "
        avail="$(run_to 30 df -Pm "$p" 2>/dev/null | awk 'NR == 2 { print $(NF - 2) }')"
        is_uint "$avail" || continue
        if [ "$mp" = "/boot" ]; then
            [ "$avail" -lt 40 ] && msg_warn "/boot has only ${avail} MB free after patching; remove old kernels"
        elif [ "$avail" -lt 200 ]; then
            msg_warn "$mp has only ${avail} MB free after patching"
        fi
    done
}

check_network() {
    is_container && return 0
    if have ip; then
        if [ -z "$(ip -4 route show default 2>/dev/null)" ] && [ -z "$(ip -6 route show default 2>/dev/null)" ]; then
            msg_warn "no default route present after patching"
        fi
    fi
}

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
main() {
    parse_args "$@"
    trap 'on_exit' EXIT
    trap 'msg_fail "post-check interrupted by signal"; exit 0' TERM INT HUP

    patch_state_init
    LOG_FILE="$STATE_DIR/post_check.log"
    : >> "$LOG_FILE" 2>/dev/null || LOG_FILE="/dev/null"
    detect_os

    if [ -z "$PATCH_ID" ] || ! [[ "$PATCH_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        msg_fail "missing or invalid --patch-id '$PATCH_ID'"
    fi

    wait_for_boot
    check_required_services
    check_previous_services
    check_failed_units
    check_kernel
    check_package_db
    check_package_diff
    check_disk_after
    check_network

    if [ "$FAIL_COUNT" -eq 0 ]; then
        log "post-check passed"
    else
        log "post-check failed with $FAIL_COUNT problem(s)"
    fi
    write_check_output || { echo "FATAL: cannot write $OUTPUT_FILE" >&2; exit 3; }
    exit 0
}

main "$@"
