#!/usr/bin/env bash
# =============================================================================
# patch_rhel.sh - apply (or roll back) package updates on Red Hat Enterprise
#                 Linux 7 / 8 / 9 / 10.
#
# Usage:
#   patch_rhel.sh --patch-id ID --mode security|all|packages
#                 [--packages "a b"] [--exclude "x y"] [--no-kernel]
#                 [--dry-run] --output FILE
#   patch_rhel.sh --rollback --patch-id ID --output FILE
#
# Behaviour
#   * subscription check first: an unregistered host without RHUI / Satellite /
#     third-party repositories cannot be patched and fails early with a clear
#     error; entitlement problems are reported as warnings
#   * mode security : "dnf|yum update --security"
#     mode all      : "dnf|yum update"
#     mode packages : "dnf|yum update <packages>"; RHSA/RHBA/RHEA ids in the
#                     package list are passed as --advisory=<id>
#   * a minor release lock (subscription-manager release --set / dnf vars) is
#     respected: the script never changes or removes it and reports it
#   * the yum/dnf history transaction id is stored in
#     /var/lib/provisioner/patch/<id>/transaction_id and in the report
#   * kpatch live patches: noted, and kpatch-patch packages are kept in sync
#     with the kernel policy (--no-kernel leaves them updatable on purpose,
#     they do not replace the running kernel)
#   * rollback: "history undo <transaction_id>" plus best effort downgrades
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

RHEL_SUB_STATE="unknown"     # registered | unregistered | rhui | no-tool | unknown
RHEL_RELEASE_LOCK=""

rhel_has_rhui_repos() {
    ls /etc/yum.repos.d/*rhui* /etc/yum.repos.d/rh-cloud*.repo > /dev/null 2>&1 && return 0
    grep -lsqE 'rhui|cds\.rhel\.updates' /etc/yum.repos.d/*.repo 2>/dev/null && return 0
    return 1
}

# Returns 1 when the host has no way to receive content.
rhel_subscription_check() {
    if ! have subscription-manager; then
        if rhel_has_rhui_repos; then
            RHEL_SUB_STATE="rhui"
            add_note "subscription-manager not installed; content is provided by cloud RHUI repositories"
        else
            RHEL_SUB_STATE="no-tool"
            add_warn "subscription-manager is not installed and no RHUI repositories were found"
        fi
        return 0
    fi

    local idout idrc
    idout="$(run_to 120 subscription-manager identity 2>&1)"
    idrc=$?
    if [ "$idrc" -eq 124 ]; then
        add_warn "subscription-manager identity timed out; continuing and letting $EL_PM decide"
        return 0
    fi
    if [ "$idrc" -ne 0 ] || ! printf '%s' "$idout" | grep -qi 'system identity:'; then
        if rhel_has_rhui_repos; then
            RHEL_SUB_STATE="rhui"
            add_note "host is not registered with subscription-manager; content is provided by RHUI"
            return 0
        fi
        RHEL_SUB_STATE="unregistered"
        add_warn "system is not registered with subscription-manager: $(flatten "${idout:0:160}")"
        return 0
    fi
    RHEL_SUB_STATE="registered"

    local stout overall
    stout="$(run_to 120 subscription-manager status 2>&1)"
    overall="$(printf '%s\n' "$stout" | awk -F': *' '/^Overall Status:/ { print $2; exit }')"
    case "$overall" in
        Current|Disabled|Registered|"") ;;
        *) add_warn "subscription status is '$overall'; some repositories may be unavailable" ;;
    esac

    # refresh entitlement certificates so that repo access does not fail with 403
    if [ "$DRY_RUN" -eq 0 ]; then
        run_logged 180 subscription-manager refresh || add_warn "subscription-manager refresh failed; continuing with existing entitlement certificates"
    fi

    local rel
    rel="$(run_to 60 subscription-manager release --show 2>/dev/null | awk -F': *' '/^Release:/ { print $2; exit }')"
    [ -n "$rel" ] && RHEL_RELEASE_LOCK="$rel"
    return 0
}

rhel_release_lock_notes() {
    local f v
    for f in /etc/dnf/vars/releasever /etc/yum/vars/releasever; do
        if [ -r "$f" ] && [ -z "$RHEL_RELEASE_LOCK" ]; then
            v="$(head -n1 "$f" 2>/dev/null | tr -d '[:space:]')"
            [ -n "$v" ] && RHEL_RELEASE_LOCK="$v"
        fi
    done
    if [ -n "$RHEL_RELEASE_LOCK" ]; then
        printf '%s\n' "$RHEL_RELEASE_LOCK" > "$STATE_DIR/releasever.lock" 2>/dev/null || true
        add_note "releasever is locked to $RHEL_RELEASE_LOCK; updates stay within that minor release (lock is respected, not changed)"
        local eus
        eus="$(run_to "$PM_TIMEOUT" "$EL_PM" -q repolist enabled 2>/dev/null | awk '$1 ~ /-(eus|e4s|aus|tus)-/ { n++ } END { print n + 0 }')"
        if [ "$(uint_or "$eus" 0)" -eq 0 ] && [ "$RHEL_RELEASE_LOCK" != "$OS_VERSION_MAJOR" ]; then
            add_warn "releasever is locked to $RHEL_RELEASE_LOCK but no EUS/E4S/AUS repository is enabled; the locked minor release may no longer receive errata"
        fi
    fi
}

rhel_kpatch_notes() {
    local loaded=""
    if have kpatch; then
        loaded="$(run_to 30 kpatch list 2>/dev/null | awk '/^Loaded patch modules:/ { f = 1; next } /^Installed patch modules:/ { f = 0 } f && NF { printf "%s ", $1 }')"
    fi
    if [ -n "${loaded// /}" ]; then
        add_note "kpatch live patches loaded ($loaded); kernel CVE fixes may already be active without reboot"
        if [ "$NO_KERNEL" -eq 1 ]; then
            add_note "--no-kernel excludes kernel* packages only; kpatch-patch-* live patch packages remain updatable"
        fi
    fi
}

# Past maintenance support: RHEL 7 needs the ELS add-on.
rhel_lifecycle_notes() {
    local now
    now="$(date -u +%Y%m%d)"
    case "$OS_VERSION_MAJOR" in
        6) add_warn "RHEL 6 is end-of-life; only ELS content (if subscribed) is available" ;;
        7) if [ "$now" -gt 20240630 ]; then
               add_warn "RHEL 7 left maintenance support on 2024-06-30; new errata require the Extended Life Cycle Support add-on"
           fi ;;
    esac
}

# With no Red Hat content and no other enabled repository there is nothing to do.
rhel_content_gate() {
    case "$RHEL_SUB_STATE" in
        unregistered|no-tool)
            local n
            n="$(el_enabled_repo_count)"
            if [ "$n" -eq 0 ]; then
                add_error "host is not registered (subscription-manager) and has no enabled repositories; register the system or attach it to Satellite/RHUI before patching"
                return 1
            fi
            add_warn "host is not registered with Red Hat; patching from $n non-Red Hat / local repositor(y/ies) only"
            ;;
    esac
    return 0
}

rhel_recover_interrupted() {
    if [ "$EL_PM" = "yum" ] && ls /var/lib/yum/transaction-all* > /dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
            add_warn "an unfinished yum transaction exists; a real run would call yum-complete-transaction first"
        elif have yum-complete-transaction; then
            add_warn "unfinished yum transaction found; running yum-complete-transaction --cleanup-only"
            run_logged "$TXN_TIMEOUT" yum-complete-transaction -y --cleanup-only || add_warn "yum-complete-transaction failed: $(log_error_tail)"
        else
            add_warn "unfinished yum transaction found and yum-utils is not installed; continuing"
        fi
    fi
    if ! run_to 120 rpm -q rpm > /dev/null 2>&1; then
        add_error "rpm database is not usable (rpm -q rpm failed); run 'rpm --rebuilddb' and retry"
        return 1
    fi
    return 0
}

main() {
    patch_init "$@"

    if ! patch_validate_args; then
        patch_finish failed
    fi
    if [ "$PKG_FAMILY" != "rpm" ]; then
        add_error "patch_rhel.sh requires rpm with yum/dnf (detected os: $OS_ID)"
        patch_finish failed
    fi
    case "$OS_ID" in
        rhel|redhat) ;;
        *) add_warn "patch_rhel.sh executed on '$OS_ID'; subscription handling may not apply" ;;
    esac
    el_detect_pm || patch_finish failed

    patch_lock_acquire || patch_finish failed

    if [ "$ROLLBACK" -eq 1 ]; then
        rhel_subscription_check
        el_rollback_main
    fi

    rhel_recover_interrupted || patch_finish failed
    rhel_subscription_check
    rhel_content_gate || patch_finish failed
    rhel_release_lock_notes
    rhel_lifecycle_notes
    rhel_kpatch_notes

    el_patch_main
}

main "$@"
