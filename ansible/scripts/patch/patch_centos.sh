#!/usr/bin/env bash
# =============================================================================
# patch_centos.sh - apply (or roll back) package updates on CentOS, CentOS
#                   Stream, Rocky Linux, AlmaLinux and Oracle Linux.
#
# Usage:
#   patch_centos.sh --patch-id ID --mode security|all|packages
#                   [--packages "a b"] [--exclude "x y"] [--no-kernel]
#                   [--dry-run] --output FILE
#   patch_centos.sh --rollback --patch-id ID --output FILE
#
# Behaviour
#   * yum (EL7) and dnf (EL8+) are both supported
#   * mode security : "<pm> update --security" when the enabled repositories
#                     ship updateinfo metadata (Rocky, Alma, Oracle, EPEL).
#                     CentOS Linux repositories never did - there "--security"
#                     silently updates nothing, so a FULL update is performed
#                     and a warning is recorded in "errors".
#     mode all      : "<pm> update"
#     mode packages : "<pm> update <packages>"; entries that look like advisory
#                     ids (RLSA-2024:1234, ELSA-2024-1234 ...) become --advisory
#   * --exclude -> --exclude=<glob>; --no-kernel -> kernel packages excluded
#   * the yum/dnf history transaction id is stored in
#     /var/lib/provisioner/patch/<id>/transaction_id and in the report
#   * rollback: "<pm> history undo <transaction_id>", then explicit downgrades
#     for anything still newer than the baseline
#   * notes for end-of-life releases and vault / dead mirror repositories
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

CENTOS_FLAVOUR="centos"    # centos | stream | rocky | almalinux | ol | other

centos_detect_flavour() {
    case "$OS_ID" in
        centos)
            if grep -qi 'stream' /etc/centos-release /etc/os-release 2>/dev/null; then
                CENTOS_FLAVOUR="stream"
            else
                CENTOS_FLAVOUR="centos"
            fi ;;
        rocky)     CENTOS_FLAVOUR="rocky" ;;
        almalinux) CENTOS_FLAVOUR="almalinux" ;;
        ol|oracle|oraclelinux) CENTOS_FLAVOUR="ol" ;;
        rhel)
            CENTOS_FLAVOUR="other"
            add_warn "patch_centos.sh executed on RHEL; patch_rhel.sh adds subscription handling"
            ;;
        *)
            CENTOS_FLAVOUR="other"
            add_warn "patch_centos.sh executed on '$OS_ID'"
            ;;
    esac
}

# End-of-life and repository sanity notes. Fatal only when no repository can
# possibly work.
centos_lifecycle_notes() {
    local now eol=""
    now="$(date -u +%Y%m%d)"
    case "$CENTOS_FLAVOUR:$OS_VERSION_MAJOR" in
        centos:6) eol="2020-11-30" ;;
        centos:7) [ "$now" -gt 20240630 ] && eol="2024-06-30" ;;
        centos:8) eol="2021-12-31" ;;
        stream:8) [ "$now" -gt 20240531 ] && eol="2024-05-31" ;;
        ol:7)     [ "$now" -gt 20241231 ] && eol="2024-12-31 (premier support)" ;;
    esac
    if [ -n "$eol" ]; then
        add_warn "$OS_PRETTY reached end-of-life on $eol; only packages already present in the frozen/vault or extended-support repositories can be installed"
    fi

    [ -d /etc/yum.repos.d ] || return 0
    local summary
    summary="$(awk '
        function flush() {
            if (name == "" || !enabled) return
            if (url ~ /vault\.centos\.org|\/centos-vault\//) v = 1
            if (url ~ /mirrorlist\.centos\.org/) m = 1
        }
        /^\[/ { flush(); name = $0; enabled = 1; url = ""; next }
        /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(0|no|false)/ { enabled = 0 }
        /^[[:space:]]*(baseurl|mirrorlist|metalink)[[:space:]]*=/ { url = url " " $0 }
        END { flush(); printf "%d %d", v + 0, m + 0 }' /etc/yum.repos.d/*.repo 2>/dev/null)"
    local vault="${summary%% *}" mirror="${summary##* }"
    if [ "$mirror" = "1" ] && { [ "$CENTOS_FLAVOUR" = "centos" ] || [ "$OS_VERSION_MAJOR" = "8" ]; }; then
        add_warn "enabled repositories use mirrorlist.centos.org, which no longer exists; metadata refresh will fail until they are pointed at vault.centos.org or an extended-support mirror"
    fi
    if [ "$vault" = "1" ]; then
        add_note "repositories point at vault.centos.org (frozen archive); a successful run does not mean the host has current security fixes"
    fi
}

# An interrupted yum transaction leaves journal files behind; finishing or
# cleaning it first avoids duplicate packages.
centos_recover_interrupted() {
    if [ "$EL_PM" = "yum" ] && ls /var/lib/yum/transaction-all* > /dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
            add_warn "an unfinished yum transaction exists; a real run would call yum-complete-transaction first"
            return 0
        fi
        add_warn "unfinished yum transaction found; attempting yum-complete-transaction"
        if have yum-complete-transaction; then
            if ! run_logged "$TXN_TIMEOUT" yum-complete-transaction -y --cleanup-only; then
                add_warn "yum-complete-transaction --cleanup-only failed: $(log_error_tail)"
            fi
        else
            add_warn "yum-complete-transaction (yum-utils) is not installed; continuing without cleanup"
        fi
    fi
    # stale rpm database lock files after a crash (rpm < 4.16 / BerkeleyDB)
    if ls /var/lib/rpm/__db.00* > /dev/null 2>&1; then
        if ! run_to 120 rpm -q rpm > /dev/null 2>&1; then
            if [ "$DRY_RUN" -eq 1 ]; then
                add_warn "rpm database does not answer queries; a real run would rebuild it"
            else
                add_warn "rpm database does not answer queries; removing stale __db files and rebuilding"
                rm -f /var/lib/rpm/__db.00* 2>/dev/null
                if ! run_logged 900 rpm --rebuilddb; then
                    add_error "rpm --rebuilddb failed: $(log_error_tail)"
                    return 1
                fi
            fi
        fi
    elif ! run_to 120 rpm -q rpm > /dev/null 2>&1; then
        add_error "rpm database is not usable (rpm -q rpm failed)"
        return 1
    fi
    return 0
}

centos_oracle_notes() {
    [ "$CENTOS_FLAVOUR" = "ol" ] || return 0
    case "$(uname -r)" in
        *uek*)
            if [ "$NO_KERNEL" -eq 1 ]; then
                add_note "Oracle UEK kernel in use; kernel-uek* packages are excluded by --no-kernel"
            fi ;;
    esac
    if have uptrack-upgrade; then
        add_note "Ksplice is installed; rebootless kernel updates are managed separately by uptrack"
    fi
}

main() {
    patch_init "$@"

    if ! patch_validate_args; then
        patch_finish failed
    fi
    if [ "$PKG_FAMILY" != "rpm" ]; then
        add_error "patch_centos.sh requires rpm with yum/dnf (detected os: $OS_ID)"
        patch_finish failed
    fi
    el_detect_pm || patch_finish failed
    centos_detect_flavour

    patch_lock_acquire || patch_finish failed

    if [ "$ROLLBACK" -eq 1 ]; then
        el_rollback_main
    fi

    centos_lifecycle_notes
    centos_oracle_notes
    centos_recover_interrupted || patch_finish failed

    if [ "$MODE" = "security" ] && [ "$CENTOS_FLAVOUR" = "centos" ]; then
        log "CentOS Linux: security metadata is normally absent; availability is probed before choosing --security"
    fi

    el_patch_main
}

main "$@"
