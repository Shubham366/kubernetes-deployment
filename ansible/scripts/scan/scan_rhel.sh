#!/usr/bin/env bash
# =============================================================================
# scan_rhel.sh - vulnerability / compliance / inventory scan for Red Hat
#                Enterprise Linux 7 / 8 / 9 / 10.
#
# Usage: scan_rhel.sh --scan-id ID --type TYPE --output FILE [--no-refresh]
#
# * subscription-manager registration / entitlement status. An unregistered
#   host (and no RHUI / Satellite repositories) yields an entry in "errors" but
#   a report is still produced.
# * pending updates: "<pm> check-update"; security classification, RHSA ids and
#   severity from "<pm> updateinfo list security"
# * reboot: needs-restarting -r, kernel comparison as fallback
# * kpatch / kernel live patching note, release (minor version) lock,
#   FIPS mode, EUS/E4S repositories, Insights registration
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

RHEL_SUB_STATE="unknown"      # registered | unregistered | rhui | satellite | no-tool | unknown
RHEL_SUB_DETAIL=""
RHEL_RELEASE_LOCK=""
RHEL_CONTENT_SOURCE=""

# ----------------------------------------------------------------------------
# Subscription / content source
# ----------------------------------------------------------------------------
rhel_has_rhui_repos() {
    ls /etc/yum.repos.d/*rhui* /etc/yum.repos.d/redhat-rhui*.repo /etc/yum.repos.d/rh-cloud*.repo > /dev/null 2>&1 && return 0
    grep -lsqE 'rhui|rhel-.*-rhui|cds\.rhel\.updates' /etc/yum.repos.d/*.repo 2>/dev/null && return 0
    rpm -qa 2>/dev/null | grep -qiE '^(rh-amazon-rhui-client|rhui-azure|google-rhui-client|rhui-)' && return 0
    return 1
}

rhel_subscription_status() {
    if ! have subscription-manager; then
        if rhel_has_rhui_repos; then
            RHEL_SUB_STATE="rhui"
            RHEL_SUB_DETAIL="subscription-manager not installed; cloud RHUI repositories provide content"
        else
            RHEL_SUB_STATE="no-tool"
            RHEL_SUB_DETAIL="subscription-manager is not installed and no RHUI repositories were found"
            add_error "subscription-manager not installed and no RHUI repositories found; the host may not receive Red Hat updates"
        fi
        return 0
    fi
    if ! is_root; then
        RHEL_SUB_STATE="unknown"
        RHEL_SUB_DETAIL="subscription status requires root"
        add_error "not root: cannot query subscription-manager"
        return 0
    fi

    local idout idrc
    idout="$(run_to 90 subscription-manager identity 2>&1)"
    idrc=$?
    if [ "$idrc" -eq 124 ]; then
        RHEL_SUB_STATE="unknown"
        RHEL_SUB_DETAIL="subscription-manager identity timed out"
        add_error "subscription-manager identity timed out; subscription status unknown"
        return 0
    fi
    if [ "$idrc" -ne 0 ] || ! printf '%s' "$idout" | grep -qi 'system identity:'; then
        if rhel_has_rhui_repos; then
            RHEL_SUB_STATE="rhui"
            RHEL_SUB_DETAIL="not registered with subscription-manager; cloud RHUI repositories provide content"
            add_error "note: host is not registered with subscription-manager; content comes from RHUI (pay-as-you-go cloud image)"
        else
            RHEL_SUB_STATE="unregistered"
            RHEL_SUB_DETAIL="system is not registered: $(flatten "${idout:0:160}")"
            add_error "RHEL system is not registered with subscription-manager (no RHUI/Satellite content found); updates and security errata are unavailable until it is registered"
        fi
        return 0
    fi

    RHEL_SUB_STATE="registered"
    local org
    org="$(printf '%s\n' "$idout" | awk -F': *' '/^org name:/ { print $2; exit }')"

    local stout strc overall
    stout="$(run_to 90 subscription-manager status 2>&1)"
    strc=$?
    overall="$(printf '%s\n' "$stout" | awk -F': *' '/^Overall Status:/ { print $2; exit }')"
    RHEL_SUB_DETAIL="registered${org:+ (org: $org)}, overall status: ${overall:-unknown}"
    case "$overall" in
        Current) ;;
        Disabled)
            # Simple Content Access: entitlement enforcement is off, content is available
            if printf '%s' "$stout" | grep -qi 'Simple Content Access'; then
                RHEL_SUB_DETAIL="$RHEL_SUB_DETAIL (Simple Content Access)"
            fi
            ;;
        Registered) ;;   # newer subscription-manager on SCA-only accounts
        Invalid|Insufficient|Expired)
            add_error "subscription status is '$overall': $(printf '%s\n' "$stout" | awk 'NF && !/^[+-]+$/ && !/System Status Details/ && !/^Overall Status/' | head -n 3 | tr '\n' ' ')"
            ;;
        Unknown|"")
            if [ "$strc" -ne 0 ]; then
                add_error "subscription-manager status returned rc=$strc with overall status '${overall:-unknown}'"
            fi
            ;;
    esac

    # Satellite / Capsule instead of the Red Hat CDN?
    local host=""
    [ -r /etc/rhsm/rhsm.conf ] && host="$(awk -F= '/^[[:space:]]*hostname[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' /etc/rhsm/rhsm.conf 2>/dev/null)"
    if [ -n "$host" ] && [ "$host" != "subscription.rhsm.redhat.com" ] && [ "$host" != "subscription.rhn.redhat.com" ]; then
        RHEL_CONTENT_SOURCE="satellite:$host"
        RHEL_SUB_DETAIL="$RHEL_SUB_DETAIL, content via $host"
    else
        RHEL_CONTENT_SOURCE="cdn"
    fi

    # minor release lock
    local rel
    rel="$(run_to 60 subscription-manager release --show 2>/dev/null | awk -F': *' '/^Release:/ { print $2; exit }')"
    if [ -n "$rel" ]; then
        RHEL_RELEASE_LOCK="$rel"
    fi
    return 0
}

rhel_release_lock_from_vars() {
    # A releasever can also be pinned through dnf/yum vars
    local f v
    for f in /etc/dnf/vars/releasever /etc/yum/vars/releasever; do
        if [ -r "$f" ]; then
            v="$(head -n1 "$f" 2>/dev/null | tr -d '[:space:]')"
            if [ -n "$v" ] && [ -z "$RHEL_RELEASE_LOCK" ]; then
                RHEL_RELEASE_LOCK="$v"
            fi
        fi
    done
}

# ----------------------------------------------------------------------------
# RHEL life cycle
# ----------------------------------------------------------------------------
# Echoes: supported|els|eol DATE
rhel_release_state() {
    local now
    now="$(date -u +%Y%m%d)"
    case "$OS_VERSION_MAJOR" in
        [1-5]) echo "eol long-ago" ;;
        6)  echo "eol 2020-11-30" ;;
        7)  if [ "$now" -gt 20240630 ]; then echo "els 2024-06-30"; else echo "supported 2024-06-30"; fi ;;
        8)  if [ "$now" -gt 20290531 ]; then echo "els 2029-05-31"; else echo "supported 2029-05-31"; fi ;;
        9)  if [ "$now" -gt 20320531 ]; then echo "els 2032-05-31"; else echo "supported 2032-05-31"; fi ;;
        10) echo "supported 2035-05-31" ;;
        *)  echo "unknown -" ;;
    esac
}

# ----------------------------------------------------------------------------
# Distro specific compliance checks
# ----------------------------------------------------------------------------
# RHEL-001 subscription
rhel_check_subscription() {
    case "$RHEL_SUB_STATE" in
        registered)
            case "$RHEL_SUB_DETAIL" in
                *"overall status: Current"*|*"Simple Content Access"*|*"overall status: Disabled"*|*"overall status: Registered"*)
                    add_check RHEL-001 "System registered and entitled (subscription-manager)" pass high "$RHEL_SUB_DETAIL" ;;
                *)
                    add_check RHEL-001 "System registered and entitled (subscription-manager)" warn high "$RHEL_SUB_DETAIL" ;;
            esac ;;
        rhui)
            add_check RHEL-001 "System registered and entitled (subscription-manager)" pass high "$RHEL_SUB_DETAIL" ;;
        unregistered|no-tool)
            add_check RHEL-001 "System registered and entitled (subscription-manager)" fail high "$RHEL_SUB_DETAIL" ;;
        *)
            add_check RHEL-001 "System registered and entitled (subscription-manager)" skip high "${RHEL_SUB_DETAIL:-subscription state could not be determined}" ;;
    esac
}

# RHEL-002 kernel live patching (kpatch)
rhel_check_kpatch() {
    local loaded="" pkgs=""
    if have kpatch; then
        loaded="$(run_to 30 kpatch list 2>/dev/null | awk '/^Loaded patch modules:/ { f = 1; next } /^Installed patch modules:/ { f = 0 } f && NF { printf "%s ", $1 }')"
    fi
    if have rpm; then
        pkgs="$(rpm -qa 'kpatch-patch*' 2>/dev/null | head -n 5 | tr '\n' ' ')"
    fi
    if [ -n "${loaded// /}" ]; then
        add_check RHEL-002 "Kernel live patching (kpatch)" pass low "live patches loaded: $loaded"
        add_error "note: kpatch live patches are loaded ($loaded); the running kernel version string ($OS_KERNEL) understates the applied kernel fixes and a pending kernel update may not need an immediate reboot"
    elif [ -n "${pkgs// /}" ]; then
        add_check RHEL-002 "Kernel live patching (kpatch)" warn low "kpatch-patch packages installed ($pkgs) but no patch module is loaded for the running kernel"
        add_error "note: kpatch-patch packages are installed but none is loaded for kernel $OS_KERNEL"
    elif have kpatch; then
        add_check RHEL-002 "Kernel live patching (kpatch)" warn low "kpatch installed, no live patches loaded"
    else
        add_check RHEL-002 "Kernel live patching (kpatch)" skip low "kpatch not installed; kernel fixes require a reboot"
    fi
}

# RHEL-003 minor release lock / EUS
rhel_check_release_lock() {
    local eus=""
    if [ -n "$EL_PM" ]; then
        eus="$(run_to "$PM_TIMEOUT" "$EL_PM" -q repolist enabled 2>/dev/null | awk '$1 ~ /-(eus|e4s|aus|tus)-/ { printf "%s ", $1 }')"
    fi
    if [ -n "$RHEL_RELEASE_LOCK" ]; then
        add_check RHEL-003 "Minor release lock (releasever)" warn low "release locked to $RHEL_RELEASE_LOCK${eus:+; extended update repos: $eus} - updates are limited to that minor release"
        add_error "note: releasever is locked to $RHEL_RELEASE_LOCK; pending updates are computed within that minor release only"
        if [ -z "$eus" ] && [ "$RHEL_RELEASE_LOCK" != "$OS_VERSION_MAJOR" ]; then
            add_error "releasever is locked to $RHEL_RELEASE_LOCK but no EUS/E4S/AUS repository is enabled; the locked minor release may no longer receive security errata"
        fi
    else
        add_check RHEL-003 "Minor release lock (releasever)" pass low "no release lock; host follows the latest minor release${eus:+ (extended update repos enabled: $eus)}"
    fi
}

# RHEL-004 FIPS mode (informational)
rhel_check_fips() {
    local fips=""
    [ -r /proc/sys/crypto/fips_enabled ] && fips="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)"
    if [ "$fips" = "1" ]; then
        add_check RHEL-004 "FIPS 140 mode" pass low "FIPS mode enabled"
    elif [ -z "$fips" ]; then
        add_check RHEL-004 "FIPS 140 mode" skip low "FIPS state not exposed by the kernel"
    else
        add_check RHEL-004 "FIPS 140 mode" warn low "FIPS mode not enabled (required only for regulated workloads)"
    fi
}

# RHEL-005 life cycle
rhel_check_release_support() {
    local st when
    # shellcheck disable=SC2046
    set -- $(rhel_release_state)
    st="${1:-unknown}"
    when="${2:--}"
    case "$st" in
        supported) add_check RHEL-005 "Release within vendor support" pass high "$OS_PRETTY is in maintenance support until $when" ;;
        els)
            add_check RHEL-005 "Release within vendor support" warn high "$OS_PRETTY left maintenance support on $when; security errata require an Extended Life Cycle Support add-on"
            add_error "$OS_PRETTY is past maintenance support ($when); without ELS no new security errata are published"
            ;;
        eol)
            add_check RHEL-005 "Release within vendor support" fail high "$OS_PRETTY is end-of-life ($when)"
            add_error "$OS_PRETTY is end-of-life ($when)"
            ;;
        *) add_check RHEL-005 "Release within vendor support" skip high "support status of $OS_PRETTY unknown to this scanner" ;;
    esac
}

# RHEL-006 repositories usable
rhel_check_repos() {
    local n
    n="$(el_enabled_repo_count)"
    if [ "$n" -eq 0 ]; then
        add_check RHEL-006 "Package repositories enabled" fail high "no enabled repositories ($RHEL_SUB_DETAIL)"
        add_error "no enabled package repositories; pending update information is unavailable"
    else
        add_check RHEL-006 "Package repositories enabled" pass high "$n enabled repo(s)"
    fi
}

# RHEL-007 Red Hat Insights (informational)
rhel_check_insights() {
    if have insights-client; then
        if [ -e /etc/insights-client/.registered ]; then
            add_check RHEL-007 "Red Hat Insights registered" pass low "insights-client registered"
        else
            add_check RHEL-007 "Red Hat Insights registered" warn low "insights-client installed but not registered"
        fi
    else
        add_check RHEL-007 "Red Hat Insights registered" skip low "insights-client not installed"
    fi
}

rhel_compliance_extras() {
    log "running RHEL specific checks"
    el_check_auto_updates
    el_check_gpgcheck
    el_check_crypto_policy
    rhel_check_subscription
    rhel_check_kpatch
    rhel_check_release_lock
    rhel_check_fips
    rhel_check_release_support
    rhel_check_repos
    rhel_check_insights
}

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
main() {
    scan_init "$@"
    detect_os

    case "$OS_ID" in
        rhel|redhat) ;;
        *) add_error "scan_rhel.sh executed on '$OS_ID'; subscription checks may not apply" ;;
    esac

    el_detect_pm || true
    el_installed_count
    el_newest_kernel

    rhel_subscription_status
    rhel_release_lock_from_vars

    if want_updates; then
        if [ "$RHEL_SUB_STATE" = "unregistered" ] || [ "$RHEL_SUB_STATE" = "no-tool" ]; then
            add_error "skipping metadata refresh: host has no Red Hat content source; pending updates are computed from whatever third-party repositories are enabled"
            # still try check-update: third-party / local mirror repos may exist
            el_collect_updates
        else
            el_refresh_cache
            el_collect_updates
            if [ -s "$PENDING_TSV" ] && [ "$EL_SECMETA" = "no" ]; then
                add_error "RHEL repositories normally ship updateinfo; its absence suggests a custom mirror synced without errata metadata"
            fi
        fi
    fi

    el_reboot_required
    collect_system

    if want_compliance; then
        run_common_compliance
        rhel_compliance_extras
    fi

    scan_finalize
}

main "$@"
