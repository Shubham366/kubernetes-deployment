#!/usr/bin/env bash
# =============================================================================
# patch_ubuntu.sh - apply (or roll back) package updates on Ubuntu / Debian.
#
# Usage:
#   patch_ubuntu.sh --patch-id ID --mode security|all|packages
#                   [--packages "a b"] [--exclude "x y"] [--no-kernel]
#                   [--dry-run] --output FILE
#   patch_ubuntu.sh --rollback --patch-id ID --output FILE
#
# Behaviour
#   * fully non-interactive apt (DEBIAN_FRONTEND=noninteractive, keep locally
#     modified configuration files: --force-confdef --force-confold)
#   * waits for other apt/dpkg processes, repairs an interrupted dpkg run
#     (dpkg --configure -a, apt-get -f install) before and after a failure
#   * mode security : only packages whose candidate comes from a *-security
#                     pocket / Debian-Security / Ubuntu Pro ESM archive
#                     (fallback: unattended-upgrade when the targeted upgrade
#                     cannot be computed)
#     mode all      : apt-get dist-upgrade
#     mode packages : apt-get install --only-upgrade <packages>
#   * --exclude / --no-kernel are implemented with "apt-mark hold"; holds set
#     by this script are released afterwards (also on failure / signals)
#   * old kernels are removed afterwards (never the running one)
#   * rollback: best effort downgrade to the versions in packages.before for
#     everything still available in the APT sources or the local .deb cache
#
# Report: see patch_common.sh (schema_version 1). Exit code is 0 whenever the
# report was written; the result is in the "status" field.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [ ! -r "$SCRIPT_DIR/patch_common.sh" ]; then
    echo "FATAL: $SCRIPT_DIR/patch_common.sh not found" >&2
    exit 3
fi
# shellcheck source=patch_common.sh
. "$SCRIPT_DIR/patch_common.sh" || { echo "FATAL: cannot load patch_common.sh" >&2; exit 3; }

export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a
export UCF_FORCE_CONFFOLD=1

APT_OPTS=(
    -y -q
    -o "Dpkg::Options::=--force-confdef"
    -o "Dpkg::Options::=--force-confold"
    -o "Dpkg::Use-Pty=0"
    -o "DPkg::Lock::Timeout=600"
    -o "Acquire::Retries=3"
    -o "APT::Get::Show-User-Simulation-Note=false"
)

HOLDS_APPLIED_FILE=""
KERNEL_NAME_RE='^linux-(image|headers|modules|generic|virtual|aws|azure|gcp|gke|oracle|kvm|lowlatency|signed|tools|cloud-tools|hwe|oem|ibm|raspi|server)'

# ----------------------------------------------------------------------------
# Locking / recovery
# ----------------------------------------------------------------------------
apt_wait_for_lock() {
    local max="${1:-600}" waited=0 holder
    while :; do
        holder="$(pgrep -x -d ' ' 'apt|apt-get|aptitude|dpkg|unattended-upgr|apt.systemd.dai' 2>/dev/null)"
        if [ -z "$holder" ]; then
            return 0
        fi
        if [ "$waited" -ge "$max" ]; then
            add_error "apt/dpkg is busy (pids: $holder) after waiting ${max}s"
            return 1
        fi
        [ $(( waited % 60 )) -eq 0 ] && log "waiting for running apt/dpkg (pids: $holder)"
        sleep 10
        waited=$(( waited + 10 ))
    done
}

# Is the dpkg database in an interrupted / half configured state?
dpkg_needs_recovery() {
    if [ -n "$(run_to 60 dpkg --audit 2>/dev/null | head -n 1)" ]; then
        return 0
    fi
    if ls /var/lib/dpkg/updates/[0-9]* > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

dpkg_recover() {
    log "repairing interrupted dpkg state (dpkg --configure -a, apt-get -f install)"
    local rc1 rc2
    run_logged "$TXN_TIMEOUT" dpkg --force-confdef --force-confold --configure -a
    rc1=$?
    run_logged "$TXN_TIMEOUT" apt-get "${APT_OPTS[@]}" -f install
    rc2=$?
    if [ "$rc1" -ne 0 ] || [ "$rc2" -ne 0 ]; then
        return 1
    fi
    return 0
}

apt_update_lists() {
    local rc
    run_logged "$PM_TIMEOUT" apt-get -q -o "DPkg::Lock::Timeout=300" -o "Acquire::Retries=3" update
    rc=$?
    if [ "$rc" -eq 124 ]; then
        add_warn "apt-get update timed out after ${PM_TIMEOUT}s; continuing with existing package lists"
    elif [ "$rc" -ne 0 ]; then
        add_warn "apt-get update failed (rc=$rc): $(log_error_tail); continuing with existing package lists"
    elif tail -n 60 "$LOG_FILE" 2>/dev/null | grep -qE '^(Err:|W: Failed to fetch|W: Some index files failed)'; then
        add_warn "apt-get update could not reach every repository: $(tail -n 60 "$LOG_FILE" | grep -E '^(Err:|W: Failed to fetch)' | head -n 2 | tr '\n' ' ')"
    fi
    return 0
}

# ----------------------------------------------------------------------------
# Holds (exclusions)
# ----------------------------------------------------------------------------
installed_names() {
    dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\n' "$@" 2>/dev/null \
        | awk -F'\t' 'substr($1, 2, 1) == "i" { print $2 }'
}

# Prints the installed packages that must not be touched (one per line).
compute_hold_list() {
    local x
    {
        for x in $EXCLUDES; do
            installed_names "$x"
        done
        if [ "$NO_KERNEL" -eq 1 ]; then
            installed_names | awk -F: '{ print $0 }' | grep -E "$KERNEL_NAME_RE" || true
        fi
    } | sort -u
}

apply_holds() {
    HOLDS_APPLIED_FILE="$STATE_DIR/holds.applied"
    local want="$WORK_DIR/holds.want" already="$WORK_DIR/holds.already"
    compute_hold_list > "$want"
    local x
    for x in $EXCLUDES; do
        if [ -z "$(installed_names "$x" | head -n 1)" ]; then
            add_note "exclude pattern '$x' matches no installed package"
        fi
    done
    [ -s "$want" ] || return 0
    apt-mark showhold 2>/dev/null | sort -u > "$already"
    # only hold (and later release) what was not already held by the admin
    local -a new=()
    local p
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if ! grep -qxF -- "$p" "$already" 2>/dev/null && ! grep -qxF -- "${p%%:*}" "$already" 2>/dev/null; then
            new[${#new[@]}]="$p"
        fi
    done < "$want"
    if [ "${#new[@]}" -eq 0 ]; then
        return 0
    fi
    printf '%s\n' "${new[@]}" >> "$HOLDS_APPLIED_FILE"
    if ! run_logged 120 apt-mark hold "${new[@]}"; then
        add_error "apt-mark hold failed for: ${new[*]}; refusing to continue because exclusions cannot be guaranteed"
        return 1
    fi
    log "held ${#new[@]} package(s) for the duration of the run"
    return 0
}

release_holds() {
    [ -n "$HOLDS_APPLIED_FILE" ] || return 0
    [ -s "$HOLDS_APPLIED_FILE" ] || return 0
    local -a held=()
    local p
    while IFS= read -r p; do
        [ -n "$p" ] && held[${#held[@]}]="$p"
    done < "$HOLDS_APPLIED_FILE"
    if [ "${#held[@]}" -gt 0 ]; then
        if run_logged 120 apt-mark unhold "${held[@]}"; then
            rm -f "$HOLDS_APPLIED_FILE" 2>/dev/null
        else
            add_warn "could not release temporary holds: ${held[*]} (run: apt-mark unhold ${held[*]})"
        fi
    fi
}

# Called from the EXIT trap in patch_common.sh
distro_cleanup() {
    release_holds
}

# ----------------------------------------------------------------------------
# Simulation parsing
# ----------------------------------------------------------------------------
# stdin: "apt-get -s" output -> name \t current \t candidate \t security
apt_sim_parse() {
    awk -v OFS='\t' '
        /^Inst / {
            name = $2; cur = ""; cand = ""; inside = ""
            if (match($0, /^Inst [^ ]+ \[[^]]*\]/)) {
                t = substr($0, RSTART, RLENGTH)
                sub(/^Inst [^ ]+ \[/, "", t)
                sub(/\]$/, "", t)
                cur = t
            }
            if (match($0, /\([^)]*\)/)) {
                inside = substr($0, RSTART + 1, RLENGTH - 2)
                split(inside, a, " ")
                cand = a[1]
            }
            sec = (inside ~ /-security|ESM|Debian-Security/) ? "true" : "false"
            print name, cur, cand, sec
        }'
}

# Filter a parsed simulation (stdin) against the hold list file $1
filter_held() {
    local holdf="$1"
    if [ ! -s "$holdf" ]; then
        cat
        return 0
    fi
    awk -F'\t' -v OFS='\t' -v holdf="$holdf" '
        BEGIN { while ((getline l < holdf) > 0) { h[l] = 1; sub(/:.*/, "", l); h[l] = 1 } close(holdf) }
        { n = $1; b = n; sub(/:.*/, "", b); if (!(n in h) && !(b in h)) print }'
}

# simulate dist-upgrade -> file with parsed lines; returns apt's exit code
simulate_dist_upgrade() {
    local outf="$1" raw="$WORK_DIR/sim_raw.out" rc
    run_to "$PM_TIMEOUT" apt-get -s "${APT_OPTS[@]}" dist-upgrade > "$raw" 2>> "$LOG_FILE"
    rc=$?
    cat "$raw" >> "$LOG_FILE" 2>/dev/null || true
    apt_sim_parse < "$raw" > "$outf" 2>/dev/null
    return "$rc"
}

# ----------------------------------------------------------------------------
# Selection per mode
# ----------------------------------------------------------------------------
# Requested packages that are installed (others are skipped with a warning).
select_requested_packages() {
    local holdf="$1" p base
    for p in $PACKAGES; do
        base="${p%%=*}"
        if [ -z "$(installed_names "$base" | head -n 1)" ]; then
            add_warn "package '$base' is not installed; skipped (patching never installs new top-level packages)"
            continue
        fi
        if [ -s "$holdf" ] && grep -qxF -- "${base%%:*}" "$holdf" 2>/dev/null; then
            add_warn "package '$base' is excluded (--exclude / --no-kernel / held); skipped"
            continue
        fi
        if apt-mark showhold 2>/dev/null | grep -qxF -- "${base%%:*}"; then
            add_warn "package '$base' is on hold (apt-mark); skipped"
            continue
        fi
        printf '%s\n' "$p"
    done
}

# ----------------------------------------------------------------------------
# Kernel housekeeping
# ----------------------------------------------------------------------------
autoremove_old_kernels() {
    local sim="$WORK_DIR/autoremove.out" running
    running="$(uname -r)"
    run_to "$PM_TIMEOUT" apt-get -s "${APT_OPTS[@]}" autoremove > "$sim" 2>> "$LOG_FILE" || return 0
    local -a victims=()
    local p
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        case "$p" in
            *"$running"*) continue ;;   # never the running kernel
        esac
        victims[${#victims[@]}]="$p"
    done < <(awk '/^Remv / { print $2 }' "$sim" | grep -E '^linux-(image|headers|modules|modules-extra|tools|cloud-tools)-[0-9]' || true)
    if [ "${#victims[@]}" -eq 0 ]; then
        log "no old kernel packages to remove"
        return 0
    fi
    log "removing ${#victims[@]} old kernel package(s): ${victims[*]}"
    if ! run_logged "$TXN_TIMEOUT" apt-get "${APT_OPTS[@]}" purge "${victims[@]}"; then
        add_warn "removal of old kernel packages failed: $(log_error_tail)"
    fi
    return 0
}

boot_space_check() {
    # a full /boot is the classic reason for a failed kernel update
    local avail
    avail="$(df -Pm /boot 2>/dev/null | awk 'NR == 2 { print $4 }')"
    if is_uint "$avail" && [ "$avail" -lt 120 ] && [ "$NO_KERNEL" -eq 0 ]; then
        add_warn "/boot has only ${avail} MB free; removing old kernels first"
        autoremove_old_kernels
    fi
}

ubuntu_reboot_required() {
    if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then
        REBOOT_REQUIRED="true"
    else
        REBOOT_REQUIRED="false"
    fi
}

# ----------------------------------------------------------------------------
# Patch
# ----------------------------------------------------------------------------
run_apt_transaction() {
    # run_apt_transaction <apt-get args...> ; retries once after a dpkg repair
    local rc
    run_logged "$TXN_TIMEOUT" apt-get "${APT_OPTS[@]}" "$@"
    rc=$?
    if [ "$rc" -eq 124 ]; then
        add_error "apt-get $1 timed out after ${TXN_TIMEOUT}s; dpkg may be left half configured (see $LOG_FILE)"
        return "$rc"
    fi
    if [ "$rc" -ne 0 ]; then
        add_warn "apt-get $1 failed (rc=$rc): $(log_error_tail); attempting dpkg recovery and one retry"
        apt_wait_for_lock 300 || true
        dpkg_recover || true
        run_logged "$TXN_TIMEOUT" apt-get "${APT_OPTS[@]}" "$@"
        rc=$?
        if [ "$rc" -ne 0 ]; then
            add_error "apt-get $1 failed again after recovery (rc=$rc): $(log_error_tail)"
        fi
    fi
    return "$rc"
}

do_dry_run() {
    local holdf="$WORK_DIR/holds.want" sim="$WORK_DIR/sim.tsv" rc
    compute_hold_list > "$holdf"
    case "$MODE" in
        all)
            simulate_dist_upgrade "$sim"; rc=$?
            filter_held "$holdf" < "$sim" | awk -F'\t' -v OFS='\t' '{ print $1, $2, $3 }' > "$UPDATED_TSV"
            ;;
        security)
            simulate_dist_upgrade "$sim"; rc=$?
            filter_held "$holdf" < "$sim" | awk -F'\t' -v OFS='\t' '$4 == "true" { print $1, $2, $3 }' > "$UPDATED_TSV"
            ;;
        packages)
            local -a req=()
            local p
            while IFS= read -r p; do
                [ -n "$p" ] && req[${#req[@]}]="$p"
            done < <(select_requested_packages "$holdf")
            if [ "${#req[@]}" -eq 0 ]; then
                add_error "none of the requested packages can be upgraded on this host: $PACKAGES"
                patch_finish failed
            fi
            local raw="$WORK_DIR/sim_pkgs.out"
            run_to "$PM_TIMEOUT" apt-get -s "${APT_OPTS[@]}" install --only-upgrade "${req[@]}" > "$raw" 2>> "$LOG_FILE"
            rc=$?
            cat "$raw" >> "$LOG_FILE" 2>/dev/null || true
            apt_sim_parse < "$raw" | awk -F'\t' -v OFS='\t' '{ print $1, $2, $3 }' > "$UPDATED_TSV"
            ;;
    esac
    if [ "${rc:-1}" -ne 0 ]; then
        add_error "apt simulation failed (rc=${rc:-?}): $(log_error_tail)"
        patch_finish failed
    fi
    ubuntu_reboot_required
    patch_finish dry_run
}

do_patch() {
    local rc=0 holdf="$WORK_DIR/holds.want"

    apt_wait_for_lock 600 || patch_finish failed

    if dpkg_needs_recovery; then
        if [ "$DRY_RUN" -eq 1 ]; then
            add_warn "dpkg database is in an interrupted state; a real run would execute 'dpkg --configure -a' first"
        else
            add_warn "dpkg database was in an interrupted state; running recovery before patching"
            if ! dpkg_recover; then
                add_error "dpkg recovery failed: $(log_error_tail)"
                patch_finish failed
            fi
        fi
    fi

    apt_update_lists

    if [ "$DRY_RUN" -eq 1 ]; then
        do_dry_run
    fi

    ensure_before_snapshot || patch_finish failed
    boot_space_check
    apply_holds || patch_finish failed
    compute_hold_list > "$holdf"

    case "$MODE" in
        all)
            run_apt_transaction dist-upgrade
            rc=$?
            ;;
        security)
            local sim="$WORK_DIR/sim.tsv" src
            simulate_dist_upgrade "$sim"
            src=$?
            local -a secpk=()
            local name
            while IFS= read -r name; do
                [ -n "$name" ] && secpk[${#secpk[@]}]="$name"
            done < <(awk -F'\t' '$4 == "true" { print $1 }' "$sim" 2>/dev/null)

            if [ "$src" -ne 0 ]; then
                add_warn "could not compute the security update set (apt-get -s dist-upgrade rc=$src): $(log_error_tail)"
                if have unattended-upgrade; then
                    add_warn "falling back to unattended-upgrade, which installs from its configured (security) origins"
                    run_logged "$TXN_TIMEOUT" unattended-upgrade -v
                    rc=$?
                    [ "$rc" -ne 0 ] && add_error "unattended-upgrade failed (rc=$rc): $(log_error_tail)"
                else
                    add_error "unattended-upgrade is not installed; no fallback for security-only patching"
                    rc=1
                fi
            elif [ "${#secpk[@]}" -eq 0 ]; then
                log "no pending security updates"
                rc=0
            else
                log "upgrading ${#secpk[@]} security package(s)"
                # remember which of them are automatically installed: "install"
                # would otherwise flag them as manually installed
                local autof="$WORK_DIR/auto.before"
                apt-mark showauto 2>/dev/null | sort -u > "$autof"
                run_apt_transaction install --only-upgrade "${secpk[@]}"
                rc=$?
                local -a reauto=()
                for name in "${secpk[@]}"; do
                    if grep -qxF -- "${name%%:*}" "$autof" 2>/dev/null || grep -qxF -- "$name" "$autof" 2>/dev/null; then
                        reauto[${#reauto[@]}]="$name"
                    fi
                done
                if [ "${#reauto[@]}" -gt 0 ]; then
                    run_logged 300 apt-mark auto "${reauto[@]}" || add_warn "could not restore the 'automatically installed' flag on some packages"
                fi
            fi
            ;;
        packages)
            local -a req=()
            local p
            while IFS= read -r p; do
                [ -n "$p" ] && req[${#req[@]}]="$p"
            done < <(select_requested_packages "$holdf")
            if [ "${#req[@]}" -eq 0 ]; then
                add_error "none of the requested packages can be upgraded on this host: $PACKAGES"
                release_holds
                patch_finish failed
            fi
            local autof="$WORK_DIR/auto.before"
            apt-mark showauto 2>/dev/null | sort -u > "$autof"
            run_apt_transaction install --only-upgrade "${req[@]}"
            rc=$?
            local -a reauto=()
            for p in "${req[@]}"; do
                p="${p%%=*}"
                if grep -qxF -- "${p%%:*}" "$autof" 2>/dev/null; then
                    reauto[${#reauto[@]}]="$p"
                fi
            done
            if [ "${#reauto[@]}" -gt 0 ]; then
                run_logged 300 apt-mark auto "${reauto[@]}" || true
            fi
            ;;
    esac

    # leave dpkg in a consistent state whatever happened
    if dpkg_needs_recovery; then
        add_warn "dpkg left packages unconfigured; running recovery"
        if ! dpkg_recover; then
            add_error "dpkg recovery after patching failed: $(log_error_tail)"
            rc=1
        fi
    fi

    release_holds

    if [ "$rc" -eq 0 ] && [ "$NO_KERNEL" -eq 0 ]; then
        autoremove_old_kernels
    fi

    record_after_snapshot || true
    ubuntu_reboot_required

    if [ "$rc" -ne 0 ]; then
        patch_finish failed
    fi
    if [ "$(updated_count)" -eq 0 ]; then
        patch_finish no_changes
    fi
    patch_finish success
}

# ----------------------------------------------------------------------------
# Rollback
# ----------------------------------------------------------------------------
# Is NAME=VERSION installable from the configured sources?
apt_version_available() {
    local name="$1" ver="$2"
    apt-cache show "${name}=${ver}" > /dev/null 2>&1
}

# Path of a cached .deb for NAME VERSION (empty when not cached)
cached_deb() {
    local name="${1%%:*}" ver="$2" enc f
    enc="${ver//:/%3a}"
    for f in /var/cache/apt/archives/"${name}_${enc}"_*.deb; do
        if [ -e "$f" ]; then
            printf '%s' "$f"
            return 0
        fi
    done
    return 1
}

do_rollback() {
    local before="$STATE_DIR/packages.before" pre="$STATE_DIR/rollback.pre"
    if [ ! -s "$before" ]; then
        add_error "no baseline ($before) found for patch id '$PATCH_ID'; nothing to roll back to"
        patch_finish failed
    fi
    apt_wait_for_lock 600 || patch_finish failed
    if dpkg_needs_recovery; then
        add_warn "dpkg database was in an interrupted state; running recovery before rollback"
        dpkg_recover || add_warn "dpkg recovery reported errors: $(log_error_tail)"
    fi
    apt_update_lists

    if ! snapshot_packages "$pre"; then
        add_error "could not snapshot current packages before rollback"
        patch_finish failed
    fi

    local missing="$WORK_DIR/missing.tsv"
    packages_missing "$before" "$pre" > "$missing" 2>/dev/null
    if [ ! -s "$missing" ]; then
        add_note "installed packages already match the baseline; nothing to roll back"
        rollback_finalize
        patch_finish "$STATUS"
    fi

    local -a specs=() debs=()
    local name wanted current deb n_unavail=0
    while IFS="$_TAB" read -r name wanted current; do
        [ -n "$name" ] || continue
        if apt_version_available "$name" "$wanted"; then
            specs[${#specs[@]}]="${name}=${wanted}"
        elif deb="$(cached_deb "$name" "$wanted")"; then
            debs[${#debs[@]}]="$deb"
        else
            n_unavail=$(( n_unavail + 1 ))
            if [ "$n_unavail" -le 25 ]; then
                add_warn "$name $wanted is no longer available in the APT sources or the local cache; cannot downgrade from ${current:-not installed}"
            fi
        fi
    done < "$missing"
    if [ "$n_unavail" -gt 25 ]; then
        add_warn "... and $(( n_unavail - 25 )) more package version(s) are no longer available"
    fi

    local -a dg_opts=( "${APT_OPTS[@]}" --allow-downgrades --allow-change-held-packages --no-install-recommends )
    # apt older than 1.1 (Ubuntu 14.04) has no --allow-downgrades
    if ! apt-get --help 2>/dev/null | grep -q -- '--allow-downgrades' && \
       ! apt-get -s --allow-downgrades install > /dev/null 2>&1; then
        dg_opts=( "${APT_OPTS[@]}" --force-yes --no-install-recommends )
    fi

    if [ "${#specs[@]}" -gt 0 ]; then
        log "downgrading ${#specs[@]} package(s) to their baseline versions"
        if ! run_logged "$TXN_TIMEOUT" apt-get "${dg_opts[@]}" install "${specs[@]}"; then
            add_warn "bulk downgrade failed: $(log_error_tail); retrying package by package"
            dpkg_needs_recovery && dpkg_recover
            local s
            for s in "${specs[@]}"; do
                run_logged "$PM_TIMEOUT" apt-get "${dg_opts[@]}" install "$s" || true
            done
        fi
    fi
    if [ "${#debs[@]}" -gt 0 ]; then
        log "installing ${#debs[@]} cached .deb file(s)"
        if ! run_logged "$TXN_TIMEOUT" dpkg --force-confdef --force-confold --force-downgrade -i "${debs[@]}"; then
            add_warn "dpkg -i of cached packages reported errors: $(log_error_tail)"
            run_logged "$TXN_TIMEOUT" apt-get "${APT_OPTS[@]}" -f install || true
        fi
    fi

    if dpkg_needs_recovery; then
        dpkg_recover || add_warn "dpkg recovery after rollback reported errors: $(log_error_tail)"
    fi

    rollback_finalize
    ubuntu_reboot_required
    if [ "$REBOOT_REQUIRED" = "true" ]; then
        add_note "a reboot is required to finish the rollback"
    fi
    local kb
    kb="$(cat "$STATE_DIR/kernel.before" 2>/dev/null)"
    if [ -n "$kb" ] && [ "$kb" != "$(uname -r)" ]; then
        add_note "running kernel $(uname -r) differs from the pre-patch kernel $kb; boot the old kernel from the GRUB menu if required"
    fi
    patch_finish "$STATUS"
}

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
main() {
    patch_init "$@"

    if ! patch_validate_args; then
        patch_finish failed
    fi
    if [ "$PKG_FAMILY" != "deb" ]; then
        add_error "patch_ubuntu.sh requires apt/dpkg (detected os: $OS_ID)"
        patch_finish failed
    fi
    case "$OS_ID" in
        ubuntu|debian) ;;
        *) add_warn "patch_ubuntu.sh executed on '$OS_ID'" ;;
    esac

    patch_lock_acquire || patch_finish failed

    if [ "$ROLLBACK" -eq 1 ]; then
        do_rollback
    else
        do_patch
    fi
}

main "$@"
