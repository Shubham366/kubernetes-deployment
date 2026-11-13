#!/usr/bin/env bash
# =============================================================================
# scan_centos.sh - vulnerability / compliance / inventory scan for CentOS,
#                  CentOS Stream, Rocky Linux, AlmaLinux and Oracle Linux.
#
# Usage: scan_centos.sh --scan-id ID --type TYPE --output FILE [--no-refresh]
#
# * yum (EL7) and dnf (EL8/9/10) are both handled
# * pending updates: "<pm> check-update"
# * security updates: "<pm> updateinfo list security" where the repositories
#   ship errata metadata (Rocky RLSA, Alma ALSA, Oracle ELSA, EPEL FEDORA-EPEL).
#   CentOS Linux 7 base/updates repositories never shipped updateinfo - in that
#   case every update is reported with security=false and a note is recorded
#   in "errors".
# * reboot: needs-restarting -r (yum-utils / dnf-utils), kernel comparison as
#   fallback
# * CentOS 7 / 8 end-of-life and vault repository notes
#
# Needs only bash (4.2+), coreutils, awk, sed, rpm and yum/dnf.
# Always writes a valid JSON report; exits 0 unless the report cannot be written.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"

# Minimal emergency report when the shared library is missing.
_emergency_report() {
    local out="" id="" type="full" prev="" a
    for a in "$@"; do
        case "$prev" in
            --output) out="$a" ;;
            --scan-id) id="$a" ;;
            --type) type="$a" ;;
        esac
        prev="$a"
    done
    [ -n "$out" ] || exit 3
    id="$(printf '%s' "$id" | tr -cd 'A-Za-z0-9._:-')"
    type="$(printf '%s' "$type" | tr -cd 'a-z')"
    mkdir -p "$(dirname "$out")" 2>/dev/null
    printf '{"schema_version":1,"scan_id":"%s","scan_type":"%s","hostname":"%s","timestamp":"%s","os":{"id":"unknown","version":"","pretty_name":"","kernel":"%s","arch":"%s"},"packages":{"installed_count":0,"updates_available":0,"security_updates":0},"pending_updates":[],"reboot_required":false,"compliance":[],"system":{"uptime_seconds":0,"disk":[],"memory_mb":{"total":0,"available":0},"failed_services":[],"listening_ports":[]},"errors":["scan_common.sh could not be loaded; no data collected"]}\n' \
        "$id" "$type" "$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-')" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$(uname -r | tr -cd 'A-Za-z0-9._+-')" "$(uname -m | tr -cd 'A-Za-z0-9._-')" > "$out" || exit 3
    exit 0
}

if [ ! -r "$SCRIPT_DIR/scan_common.sh" ]; then
    echo "FATAL: $SCRIPT_DIR/scan_common.sh not found" >&2
    _emergency_report "$@"
fi
# shellcheck source=scan_common.sh
. "$SCRIPT_DIR/scan_common.sh" || _emergency_report "$@"

CENTOS_IS_STREAM=0
CENTOS_FLAVOUR="centos"     # centos | stream | rocky | almalinux | ol | other

# ----------------------------------------------------------------------------
# Flavour detection
# ----------------------------------------------------------------------------
centos_detect_flavour() {
    case "$OS_ID" in
        centos)
            if grep -qi 'stream' /etc/centos-release /etc/os-release 2>/dev/null; then
                CENTOS_IS_STREAM=1
                CENTOS_FLAVOUR="stream"
            else
                CENTOS_FLAVOUR="centos"
            fi
            ;;
        rocky)      CENTOS_FLAVOUR="rocky" ;;
        almalinux)  CENTOS_FLAVOUR="almalinux" ;;
        ol|oracle|oraclelinux) CENTOS_FLAVOUR="ol" ;;
        rhel)
            CENTOS_FLAVOUR="other"
            add_error "scan_centos.sh executed on RHEL; use scan_rhel.sh for subscription aware checks"
            ;;
        *)
            CENTOS_FLAVOUR="other"
            add_error "scan_centos.sh executed on '$OS_ID'; results may be incomplete"
            ;;
    esac
}

# Echoes: supported | eol | unknown    (and the EOL date as second word)
centos_release_state() {
    local now major="$OS_VERSION_MAJOR"
    now="$(date -u +%Y%m%d)"
    case "$CENTOS_FLAVOUR" in
        centos)
            case "$major" in
                [1-5]) echo "eol long-ago" ;;
                6) echo "eol 2020-11-30" ;;
                7) if [ "$now" -gt 20240630 ]; then echo "eol 2024-06-30"; else echo "supported 2024-06-30"; fi ;;
                8) echo "eol 2021-12-31" ;;
                *) echo "unknown -" ;;
            esac ;;
        stream)
            case "$major" in
                8) if [ "$now" -gt 20240531 ]; then echo "eol 2024-05-31"; else echo "supported 2024-05-31"; fi ;;
                9) if [ "$now" -gt 20270531 ]; then echo "eol 2027-05-31"; else echo "supported 2027-05-31"; fi ;;
                10) echo "supported 2030-01-01" ;;
                *) echo "unknown -" ;;
            esac ;;
        rocky|almalinux)
            case "$major" in
                8) if [ "$now" -gt 20290531 ]; then echo "eol 2029-05-31"; else echo "supported 2029-05-31"; fi ;;
                9) if [ "$now" -gt 20320531 ]; then echo "eol 2032-05-31"; else echo "supported 2032-05-31"; fi ;;
                10) echo "supported 2035-05-31" ;;
                *) echo "unknown -" ;;
            esac ;;
        ol)
            case "$major" in
                [1-6]) echo "eol premier-support-ended" ;;
                7) if [ "$now" -gt 20241231 ]; then echo "eol 2024-12-31"; else echo "supported 2024-12-31"; fi ;;
                8) if [ "$now" -gt 20290731 ]; then echo "eol 2029-07-31"; else echo "supported 2029-07-31"; fi ;;
                9) if [ "$now" -gt 20320630 ]; then echo "eol 2032-06-30"; else echo "supported 2032-06-30"; fi ;;
                *) echo "unknown -" ;;
            esac ;;
        *) echo "unknown -" ;;
    esac
}

# ----------------------------------------------------------------------------
# Repository sanity (EOL / vault / dead mirrorlist)
# ----------------------------------------------------------------------------
CENTOS_REPO_NOTES=""

centos_repo_inspection() {
    [ -d /etc/yum.repos.d ] || return 0
    local uses_vault=0 uses_mirrorlist=0 uses_els=0
    # look only at enabled repository sections
    local summary
    summary="$(awk '
        function flush() {
            if (name == "" || !enabled) return
            if (url ~ /vault\.centos\.org|vault\.epel|archive\.kernel\.org\/centos-vault|\/centos-vault\//) v = 1
            if (url ~ /mirrorlist\.centos\.org/) m = 1
            if (url ~ /(tuxcare|cloudlinux|els\.|\/els\/|ctrliq|perforce|openlogic)/) e = 1
        }
        /^\[/ { flush(); name = $0; enabled = 1; url = ""; next }
        /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(0|no|false)/ { enabled = 0 }
        /^[[:space:]]*(baseurl|mirrorlist|metalink)[[:space:]]*=/ { url = url " " $0 }
        END { flush(); printf "%d %d %d", v + 0, m + 0, e + 0 }' /etc/yum.repos.d/*.repo 2>/dev/null)"
    # shellcheck disable=SC2086
    set -- $summary
    uses_vault="${1:-0}"
    uses_mirrorlist="${2:-0}"
    uses_els="${3:-0}"
    CENTOS_REPO_NOTES="vault=$uses_vault mirrorlist.centos.org=$uses_mirrorlist third-party-els=$uses_els"

    if [ "$CENTOS_FLAVOUR" = "centos" ] || { [ "$CENTOS_FLAVOUR" = "stream" ] && [ "$OS_VERSION_MAJOR" = "8" ]; }; then
        if [ "$uses_mirrorlist" = "1" ]; then
            add_error "enabled repositories still point at mirrorlist.centos.org, which was shut down after EOL; yum/dnf metadata refresh will fail until the repos are switched to vault.centos.org or an extended-support provider"
        fi
        if [ "$uses_vault" = "1" ]; then
            add_error "note: repositories point at vault.centos.org - a frozen archive that receives no further security fixes; 'no pending updates' does not mean the host is patched"
        fi
        if [ "$uses_els" = "1" ]; then
            add_error "note: an extended lifecycle support (ELS) repository appears to be configured"
        fi
    fi
}

# CENTOS-001 release support state
centos_check_release_support() {
    local st when
    # shellcheck disable=SC2046
    set -- $(centos_release_state)
    st="${1:-unknown}"
    when="${2:--}"
    case "$st" in
        supported)
            add_check CENTOS-001 "Release within vendor support" pass high "$OS_PRETTY is supported until $when" ;;
        eol)
            add_check CENTOS-001 "Release within vendor support" fail high "$OS_PRETTY reached end-of-life ($when) and receives no security updates from the vendor"
            add_error "$OS_PRETTY is end-of-life ($when); update counts only reflect what the frozen repositories still offer"
            ;;
        *)
            add_check CENTOS-001 "Release within vendor support" skip high "support status of $OS_PRETTY unknown to this scanner" ;;
    esac
}

# CENTOS-002 repositories reachable / usable
centos_check_repos() {
    local n
    n="$(el_enabled_repo_count)"
    if [ "$n" -eq 0 ]; then
        add_check CENTOS-002 "Package repositories configured and usable" fail high "no enabled repositories reported by $EL_PM ($CENTOS_REPO_NOTES)"
        add_error "no enabled package repositories; pending update information is unavailable"
        return 0
    fi
    case "$CENTOS_REPO_NOTES" in
        *"mirrorlist.centos.org=1"*)
            if [ "$CENTOS_FLAVOUR" = "centos" ] || [ "$OS_VERSION_MAJOR" = "8" ]; then
                add_check CENTOS-002 "Package repositories configured and usable" fail high "$n enabled repo(s) but some use the retired mirrorlist.centos.org ($CENTOS_REPO_NOTES)"
                return 0
            fi
            ;;
    esac
    case "$CENTOS_REPO_NOTES" in
        *"vault=1"*)
            add_check CENTOS-002 "Package repositories configured and usable" warn high "$n enabled repo(s); frozen vault repositories in use ($CENTOS_REPO_NOTES)" ;;
        *)
            add_check CENTOS-002 "Package repositories configured and usable" pass high "$n enabled repo(s) ($CENTOS_REPO_NOTES)" ;;
    esac
}

# CENTOS-003 security errata metadata available
centos_check_secmeta() {
    if [ "$EL_SECMETA" = "unknown" ]; then
        el_has_security_metadata || true
    fi
    if [ "$EL_SECMETA" = "yes" ]; then
        add_check CENTOS-003 "Security errata metadata available" pass medium "updateinfo metadata is published by the enabled repositories"
    else
        local hint="security-only patching is not possible; full updates are required"
        [ "$CENTOS_FLAVOUR" = "centos" ] && hint="CentOS Linux never published updateinfo for base/updates; $hint"
        add_check CENTOS-003 "Security errata metadata available" warn medium "no updateinfo metadata - $hint"
    fi
}

# CENTOS-004 tooling needed for accurate reboot detection
centos_check_tooling() {
    if have needs-restarting; then
        add_check CENTOS-004 "needs-restarting available (yum-utils/dnf-utils)" pass low "needs-restarting present"
    else
        add_check CENTOS-004 "needs-restarting available (yum-utils/dnf-utils)" warn low "yum-utils / dnf-utils not installed; reboot detection falls back to kernel version comparison"
    fi
}

# CENTOS-005 Oracle Linux Ksplice / UEK note, duplicate packages
centos_check_misc() {
    if [ "$CENTOS_FLAVOUR" = "ol" ]; then
        if have uptrack-uname; then
            local eff
            eff="$(uptrack-uname -r 2>/dev/null)"
            add_error "note: Ksplice is installed; effective kernel is ${eff:-unknown} (running image $OS_KERNEL)"
        fi
        case "$OS_KERNEL" in
            *uek*) add_error "note: host runs the Unbreakable Enterprise Kernel ($OS_KERNEL); kernel advisories are ELSA ids for kernel-uek" ;;
        esac
    fi
    if have package-cleanup; then
        local dupes
        dupes="$(run_to 120 package-cleanup --dupes -q 2>/dev/null | head -n 10 | tr '\n' ' ')"
        if [ -n "${dupes// /}" ]; then
            add_check CENTOS-005 "No duplicate packages in the rpm database" fail medium "duplicates (interrupted transaction?): $dupes"
            add_error "duplicate packages in rpmdb suggest an interrupted yum/dnf transaction: $dupes"
        else
            add_check CENTOS-005 "No duplicate packages in the rpm database" pass medium "no duplicates reported by package-cleanup"
        fi
    elif ls /var/lib/yum/transaction-all* > /dev/null 2>&1; then
        add_check CENTOS-005 "No duplicate packages in the rpm database" fail medium "unfinished yum transaction files in /var/lib/yum (run yum-complete-transaction)"
        add_error "unfinished yum transaction detected in /var/lib/yum"
    else
        add_check CENTOS-005 "No duplicate packages in the rpm database" skip medium "package-cleanup not available"
    fi
}

centos_compliance_extras() {
    log "running EL (CentOS family) specific checks"
    el_check_auto_updates
    el_check_gpgcheck
    el_check_crypto_policy
    centos_check_release_support
    centos_check_repos
    centos_check_secmeta
    centos_check_tooling
    centos_check_misc
}

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
main() {
    scan_init "$@"
    detect_os
    centos_detect_flavour
    el_detect_pm || true

    el_installed_count
    el_newest_kernel
    centos_repo_inspection

    if want_updates; then
        el_refresh_cache
        el_collect_updates
        if [ "$CENTOS_FLAVOUR" = "centos" ] && [ "$OS_VERSION_MAJOR" = "7" ] && [ "$EL_SECMETA" != "yes" ]; then
            add_error "note: CentOS 7 repositories carry no CESA metadata; map pending updates against the CESA announcements or an external vulnerability feed for accurate security classification"
        fi
    fi

    el_reboot_required
    collect_system

    if want_compliance; then
        run_common_compliance
        centos_compliance_extras
    fi

    scan_finalize
}

main "$@"
