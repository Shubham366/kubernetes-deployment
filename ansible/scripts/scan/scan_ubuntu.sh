#!/usr/bin/env bash
# =============================================================================
# scan_ubuntu.sh - vulnerability / compliance / inventory scan for Ubuntu and
#                  Debian hosts.
#
# Usage: scan_ubuntu.sh --scan-id ID --type TYPE --output FILE [--no-refresh]
#
# * pending updates: "apt-get -s dist-upgrade" (fallback: "apt list --upgradable")
# * security updates: candidate comes from a *-security pocket, Debian-Security
#   or an Ubuntu Pro ESM archive (esm-infra / esm-apps) when visible
# * reboot: /var/run/reboot-required
# * extras: held packages, unattended-upgrades state, Ubuntu Pro / ESM status,
#   release support status, dpkg consistency, unauthenticated APT sources
#
# Needs only bash, coreutils, awk, sed and the distro's own package tools.
# Always writes a valid JSON report; exits 0 unless the report cannot be written.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"

# Minimal emergency report when the shared library is missing.
_emergency_report() {
    local out="" id="" type="full" prev=""
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

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

APT_SIM_OUT=""
APT_ESM_INFRA_PENDING=0
APT_ESM_APPS_PENDING=0

# ----------------------------------------------------------------------------
# Package inventory
# ----------------------------------------------------------------------------
ubuntu_installed_count() {
    if ! have dpkg-query; then
        add_error "dpkg-query not found; installed package count unavailable"
        return 0
    fi
    local n
    n="$(run_to 120 dpkg-query -W -f='${db:Status-Abbrev}\n' 2>/dev/null | grep -c '^ii')"
    PKG_INSTALLED_COUNT="$(uint_or "$n" 0)"
    if [ "$PKG_INSTALLED_COUNT" -eq 0 ]; then
        add_error "dpkg-query returned no installed packages (dpkg database locked or damaged?)"
    fi
}

# ----------------------------------------------------------------------------
# Metadata refresh
# ----------------------------------------------------------------------------
ubuntu_refresh_cache() {
    [ "$REFRESH_CACHE" -eq 1 ] || { log "apt-get update skipped (--no-refresh)"; return 0; }
    if ! have apt-get; then
        add_error "apt-get not found; cannot refresh package lists"
        return 0
    fi
    if ! is_root; then
        add_error "not root: skipping apt-get update; results may be based on stale package lists"
        return 0
    fi
    log "running apt-get update"
    local out="$WORK_DIR/apt_update.out" rc
    run_to "$PM_TIMEOUT" apt-get update -q -o DPkg::Lock::Timeout=120 -o Acquire::Retries=2 > "$out" 2>&1
    rc=$?
    if [ "$rc" -eq 124 ]; then
        add_error "apt-get update timed out after ${PM_TIMEOUT}s; results may be based on stale package lists"
        return 0
    fi
    if [ "$rc" -ne 0 ]; then
        add_error "apt-get update failed (rc=$rc): $(grep -E '^(E|W|Err):?' "$out" 2>/dev/null | head -n 3 | tr '\n' ' ')"
        return 0
    fi
    # rc 0 does not mean every source was reachable
    local failed
    failed="$(grep -E '^(Err:|W: Failed to fetch|W: Some index files failed|W: GPG error|E: )' "$out" 2>/dev/null | head -n 3 | tr '\n' ' ')"
    if [ -n "$failed" ]; then
        add_error "apt-get update completed with problems: $failed"
    fi
    return 0
}

ubuntu_cache_age_note() {
    # Warn when package lists are old and we did not refresh them.
    [ "$REFRESH_CACHE" -eq 0 ] || return 0
    local stamp="" now age
    if [ -e /var/lib/apt/periodic/update-success-stamp ]; then
        stamp=/var/lib/apt/periodic/update-success-stamp
    elif [ -d /var/lib/apt/lists ]; then
        stamp=/var/lib/apt/lists
    fi
    [ -n "$stamp" ] || return 0
    now="$(date +%s)"
    age=$(( now - $(stat -c %Y "$stamp" 2>/dev/null || echo "$now") ))
    if [ "$age" -gt 604800 ]; then
        add_error "package lists were last refreshed $(( age / 86400 )) days ago and --no-refresh was given; pending updates may be incomplete"
    fi
}

# ----------------------------------------------------------------------------
# Pending updates
# ----------------------------------------------------------------------------
# Parse "apt-get -s" output (stdin) into the PENDING_TSV format.
#   Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-security [amd64])
#   Inst newpkg (1.0 Ubuntu:22.04/jammy-updates [amd64])
ubuntu_parse_simulation() {
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
            sec = "false"
            if (inside ~ /-security|ESM|Debian-Security/) sec = "true"
            print name, cur, cand, sec, "", "unknown"
        }'
}

# Parse "apt list --upgradable" output (stdin) into the PENDING_TSV format.
#   openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.12 amd64 [upgradable from: 3.0.2-0ubuntu1.10]
ubuntu_parse_apt_list() {
    awk -v OFS='\t' '
        /\[upgradable from: / {
            split($1, p, "/"); name = p[1]; pockets = p[2]
            cand = $2
            cur = $0; sub(/.*\[upgradable from: /, "", cur); sub(/\].*/, "", cur)
            sec = "false"
            if (pockets ~ /-security|esm|ESM/) sec = "true"
            print name, cur, cand, sec, "", "unknown"
        }'
}

ubuntu_collect_updates() {
    if ! have apt-get; then
        add_error "apt-get not found; pending updates unavailable"
        return 0
    fi
    log "collecting pending updates (apt-get -s dist-upgrade)"
    APT_SIM_OUT="$WORK_DIR/apt_sim.out"
    local rc parsed="$WORK_DIR/apt_parsed.tsv"
    run_to "$PM_TIMEOUT" apt-get -s -q -o Debug::NoLocking=true -o APT::Get::Show-User-Simulation-Note=false dist-upgrade > "$APT_SIM_OUT" 2> "$WORK_DIR/apt_sim.err"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        ubuntu_parse_simulation < "$APT_SIM_OUT" > "$parsed" 2>/dev/null
        cat "$parsed" >> "$PENDING_TSV" 2>/dev/null
        # kept-back packages (phased updates, held packages) are informational
        local kept
        kept="$(awk '/^The following packages have been kept back:/ { f = 1; next } f && /^ / { printf "%s", $0; next } f { exit }' "$APT_SIM_OUT" 2>/dev/null | tr -s ' ' | sed 's/^ //')"
        if [ -n "$kept" ]; then
            local nk
            nk="$(printf '%s' "$kept" | wc -w | tr -d ' ')"
            add_error "note: $nk package(s) kept back by apt (held, phased or needing manual resolution): $(printf '%s' "$kept" | cut -c1-300)"
        fi
    else
        if [ "$rc" -eq 124 ]; then
            add_error "apt-get -s dist-upgrade timed out after ${PM_TIMEOUT}s; trying apt list --upgradable"
        else
            add_error "apt-get -s dist-upgrade failed (rc=$rc): $(first_line "$WORK_DIR/apt_sim.err"); trying apt list --upgradable"
        fi
        if have apt; then
            run_to "$PM_TIMEOUT" apt list --upgradable 2>/dev/null | ubuntu_parse_apt_list > "$parsed" 2>/dev/null
            if [ -s "$parsed" ]; then
                cat "$parsed" >> "$PENDING_TSV" 2>/dev/null
            else
                add_error "apt list --upgradable returned nothing usable; pending updates unknown"
            fi
        else
            add_error "apt command not available for fallback; pending updates unknown"
        fi
    fi

    # ESM updates that exist but are not installable without Ubuntu Pro show up
    # in the apt-cache policy of "ubuntu-advantage"/"pro" tooling only; count
    # what the simulation attributed to ESM archives.
    if [ -s "$APT_SIM_OUT" ]; then
        APT_ESM_INFRA_PENDING="$(grep -c '^Inst .*UbuntuESM:' "$APT_SIM_OUT" 2>/dev/null)"
        APT_ESM_APPS_PENDING="$(grep -c '^Inst .*UbuntuESMApps:' "$APT_SIM_OUT" 2>/dev/null)"
        APT_ESM_INFRA_PENDING="$(uint_or "$APT_ESM_INFRA_PENDING" 0)"
        APT_ESM_APPS_PENDING="$(uint_or "$APT_ESM_APPS_PENDING" 0)"
    fi
    return 0
}

# ----------------------------------------------------------------------------
# Reboot / kernel
# ----------------------------------------------------------------------------
ubuntu_reboot_required() {
    if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then
        REBOOT_REQUIRED="true"
        if [ -r /var/run/reboot-required.pkgs ]; then
            local pk
            pk="$(sort -u /var/run/reboot-required.pkgs 2>/dev/null | head -n 15 | tr '\n' ' ')"
            [ -n "$pk" ] && log "reboot required by: $pk"
        fi
    else
        REBOOT_REQUIRED="false"
    fi
}

ubuntu_newest_kernel() {
    # Newest installed kernel image with the same flavour as the running kernel.
    local running="$OS_KERNEL" flavour newest=""
    flavour="${running##*-}"
    if have dpkg-query; then
        newest="$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-[0-9]*' 'linux-image-unsigned-[0-9]*' 2>/dev/null \
            | awk '$1 == "ii" { print $2 }' \
            | sed -e 's/^linux-image-unsigned-//' -e 's/^linux-image-//' \
            | grep -E -- "-${flavour}\$" | sort -V | tail -n1)"
        if [ -z "$newest" ]; then
            # Debian style: linux-image-6.1.0-18-amd64 (flavour = arch), or no flavour match
            newest="$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-[0-9]*' 2>/dev/null \
                | awk '$1 == "ii" { print $2 }' | sed 's/^linux-image-//' | sort -V | tail -n1)"
        fi
    fi
    if [ -z "$newest" ]; then
        local f
        newest="$(for f in /boot/vmlinuz-*; do [ -e "$f" ] && printf '%s\n' "${f#/boot/vmlinuz-}"; done | sort -V | tail -n1)"
    fi
    NEWEST_INSTALLED_KERNEL="$newest"
}

# ----------------------------------------------------------------------------
# Distro specific compliance checks
# ----------------------------------------------------------------------------
apt_config_value() {
    # apt_config_value APT::Periodic::Unattended-Upgrade
    have apt-config || return 0
    apt-config dump 2>/dev/null | awk -v k="$1" '$1 == k { v = $2; gsub(/[";]/, "", v); print v; exit }'
}

# UPD-001 unattended-upgrades state
ubuntu_check_auto_updates() {
    local installed="no" uu lists timer="unknown" origins=""
    if have dpkg-query && dpkg-query -W -f='${db:Status-Abbrev}' unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        installed="yes"
    fi
    uu="$(apt_config_value 'APT::Periodic::Unattended-Upgrade')"
    lists="$(apt_config_value 'APT::Periodic::Update-Package-Lists')"
    if have systemctl; then
        if svc_enabled apt-daily-upgrade.timer; then timer="enabled"; else timer="disabled"; fi
    fi
    if [ -r /etc/apt/apt.conf.d/50unattended-upgrades ]; then
        if grep -vE '^[[:space:]]*//' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -qE '(-security|label=Debian-Security|codename=.*-security)'; then
            origins="security origin allowed"
        else
            origins="security origin not found in allowed origins"
        fi
    fi
    local detail="package installed: $installed, APT::Periodic::Unattended-Upgrade=${uu:-unset}, Update-Package-Lists=${lists:-unset}, apt-daily-upgrade.timer: $timer${origins:+, $origins}"
    if [ "$installed" != "yes" ]; then
        add_check UPD-001 "Automatic updates configured" fail medium "unattended-upgrades is not installed"
    elif [ "${uu:-0}" = "0" ] || [ -z "$uu" ]; then
        add_check UPD-001 "Automatic updates configured" fail medium "$detail"
    elif [ "$timer" = "disabled" ]; then
        add_check UPD-001 "Automatic updates configured" warn medium "$detail"
    elif [ "${lists:-0}" = "0" ]; then
        add_check UPD-001 "Automatic updates configured" warn medium "$detail"
    else
        add_check UPD-001 "Automatic updates configured" pass medium "$detail"
    fi
}

# UBU-001 held packages
ubuntu_check_holds() {
    if ! have apt-mark; then
        add_check UBU-001 "No packages on hold" skip low "apt-mark not available"
        return 0
    fi
    local held n
    held="$(run_to 60 apt-mark showhold 2>/dev/null | tr '\n' ' ')"
    if [ -z "${held// /}" ]; then
        add_check UBU-001 "No packages on hold" pass low "no held packages"
    else
        n="$(printf '%s' "$held" | wc -w | tr -d ' ')"
        add_check UBU-001 "No packages on hold" warn low "$n held package(s) will not receive updates: $held"
        add_error "note: held packages excluded from upgrades: $held"
    fi
}

# UBU-002 Ubuntu Pro / ESM
ubuntu_check_pro() {
    if [ "$OS_ID" != "ubuntu" ]; then
        add_check UBU-002 "Ubuntu Pro / ESM coverage" skip low "not an Ubuntu system"
        return 0
    fi
    local tool=""
    if have pro; then tool="pro"; elif have ua; then tool="ua"; elif have ubuntu-advantage; then tool="ubuntu-advantage"; fi
    if [ -z "$tool" ]; then
        add_check UBU-002 "Ubuntu Pro / ESM coverage" skip low "ubuntu-advantage-tools not installed; ESM status unknown"
        return 0
    fi
    local st="$WORK_DIR/pro_status.out"
    run_to 60 "$tool" status > "$st" 2>/dev/null
    local infra apps livepatch attached="no"
    infra="$(awk '$1 == "esm-infra" { print $2 "/" $3; exit }' "$st" 2>/dev/null)"
    apps="$(awk '$1 == "esm-apps" { print $2 "/" $3; exit }' "$st" 2>/dev/null)"
    livepatch="$(awk '$1 == "livepatch" { print $2 "/" $3; exit }' "$st" 2>/dev/null)"
    if grep -qiE '^(Subscription|Account|Contract):' "$st" 2>/dev/null; then
        attached="yes"
    fi
    if grep -qi 'not attached' "$st" 2>/dev/null; then
        attached="no"
    fi
    local detail="attached: $attached, esm-infra: ${infra:-n/a}, esm-apps: ${apps:-n/a}, livepatch: ${livepatch:-n/a}; pending ESM updates visible: infra=$APT_ESM_INFRA_PENDING apps=$APT_ESM_APPS_PENDING"
    local eol
    eol="$(ubuntu_release_state)"
    if [ "$attached" = "yes" ]; then
        add_check UBU-002 "Ubuntu Pro / ESM coverage" pass low "$detail"
    elif [ "$eol" = "esm-only" ]; then
        add_check UBU-002 "Ubuntu Pro / ESM coverage" fail high "release is past standard support and the host is not attached to Ubuntu Pro - no security updates are being received ($detail)"
        add_error "Ubuntu $OS_VERSION is past standard support and not attached to Ubuntu Pro; ESM security updates are not visible to this scan"
    else
        add_check UBU-002 "Ubuntu Pro / ESM coverage" warn low "$detail (universe packages only get security fixes through esm-apps)"
    fi
    case "$livepatch" in
        yes/enabled*) add_error "note: Canonical Livepatch is enabled; some kernel fixes are applied without reboot" ;;
    esac
}

# Echoes: supported | esm-only | eol | interim | unknown
ubuntu_release_state() {
    local now end=""
    now="$(date -u +%Y%m)"
    if [ "$OS_ID" = "ubuntu" ]; then
        case "$OS_VERSION" in
            14.04) end=201904 ;;
            16.04) end=202104 ;;
            18.04) end=202305 ;;
            20.04) end=202505 ;;
            22.04) end=202706 ;;
            24.04) end=202906 ;;
            26.04) end=203106 ;;
            *)
                # interim releases are supported for 9 months only
                if [[ "$OS_VERSION" =~ ^([0-9]{2})\.([0-9]{2})$ ]]; then
                    local y="${BASH_REMATCH[1]}" m="${BASH_REMATCH[2]}" rel endm
                    rel=$(( (2000 + 10#$y) * 12 + 10#$m - 1 ))
                    endm=$(( rel + 9 ))
                    end="$(printf '%04d%02d' $(( endm / 12 )) $(( endm % 12 + 1 )))"
                    if [ "$now" -gt "$end" ]; then echo "eol"; else echo "interim"; fi
                    return 0
                fi
                echo "unknown"; return 0 ;;
        esac
        if [ "$now" -gt "$end" ]; then echo "esm-only"; else echo "supported"; fi
        return 0
    fi
    if [ "$OS_ID" = "debian" ]; then
        case "$OS_VERSION_MAJOR" in
            [1-9])  echo "eol" ;;
            10)     echo "eol" ;;
            11)     if [ "$now" -gt 202608 ]; then echo "eol"; else echo "esm-only"; fi ;;   # LTS only
            12)     if [ "$now" -gt 202806 ]; then echo "eol"; else echo "supported"; fi ;;
            13)     echo "supported" ;;
            *)      echo "unknown" ;;
        esac
        return 0
    fi
    echo "unknown"
}

# UBU-003 release still receives security updates
ubuntu_check_release_support() {
    local st
    st="$(ubuntu_release_state)"
    case "$st" in
        supported) add_check UBU-003 "Release within vendor support" pass high "$OS_PRETTY is within standard security support" ;;
        interim)   add_check UBU-003 "Release within vendor support" warn medium "$OS_PRETTY is an interim (non-LTS) release with a 9 month support window" ;;
        esm-only)  add_check UBU-003 "Release within vendor support" warn high "$OS_PRETTY is past standard support; security updates require Ubuntu Pro ESM / Debian LTS" ;;
        eol)
            add_check UBU-003 "Release within vendor support" fail high "$OS_PRETTY is end-of-life and no longer receives security updates"
            add_error "$OS_PRETTY is end-of-life; 'no pending updates' does not mean the host is patched"
            ;;
        *)         add_check UBU-003 "Release within vendor support" skip high "support status of $OS_PRETTY unknown to this scanner" ;;
    esac
}

# UBU-004 dpkg database consistency
ubuntu_check_dpkg_state() {
    if ! have dpkg; then
        add_check UBU-004 "dpkg database consistent" skip medium "dpkg not available"
        return 0
    fi
    local audit broken
    audit="$(run_to 60 dpkg --audit 2>/dev/null | head -n 20)"
    broken="$(run_to 60 dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 !~ /^(ii|rc|hi|un|pn)$/ { printf "%s(%s) ", $2, $1 }' | cut -c1-300)"
    if [ -z "$audit" ] && [ -z "$broken" ]; then
        add_check UBU-004 "dpkg database consistent" pass medium "no half-installed or unconfigured packages"
    else
        add_check UBU-004 "dpkg database consistent" fail medium "packages in inconsistent state: ${broken:-see dpkg --audit}"
        add_error "dpkg reports packages in an inconsistent state: ${broken:-see dpkg --audit}"
    fi
}

# UBU-005 unauthenticated APT sources
ubuntu_check_apt_auth() {
    local bad=""
    if grep -rhsE '^[[:space:]]*deb.*\[[^]]*trusted=yes' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null | grep -q .; then
        bad="$bad sources with [trusted=yes]"
    fi
    if grep -rhsiE '^[[:space:]]*Trusted:[[:space:]]*yes' /etc/apt/sources.list.d 2>/dev/null | grep -q .; then
        bad="$bad deb822 sources with Trusted: yes;"
    fi
    local v
    v="$(apt_config_value 'APT::Get::AllowUnauthenticated')"
    case "$v" in true|1|yes) bad="$bad APT::Get::AllowUnauthenticated=$v;" ;; esac
    v="$(apt_config_value 'Acquire::AllowInsecureRepositories')"
    case "$v" in true|1|yes) bad="$bad Acquire::AllowInsecureRepositories=$v;" ;; esac
    if [ -z "$bad" ]; then
        add_check UBU-005 "APT repositories authenticated" pass high "no unauthenticated / trusted=yes APT sources"
    else
        add_check UBU-005 "APT repositories authenticated" fail high "signature verification bypassed:$bad"
    fi
}

# UBU-006 security pocket configured
ubuntu_check_security_pocket() {
    local found=0
    if grep -rhsE '^[[:space:]]*deb[[:space:]].*(-security|debian-security)' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null | grep -q .; then
        found=1
    fi
    if grep -rhsE '^[[:space:]]*Suites:.*-security' /etc/apt/sources.list.d 2>/dev/null | grep -q .; then
        found=1
    fi
    if [ "$found" -eq 1 ]; then
        add_check UBU-006 "Security update repository configured" pass high "a -security pocket is present in the APT sources"
    else
        add_check UBU-006 "Security update repository configured" fail high "no -security pocket in /etc/apt/sources.list*; security updates cannot be identified or installed"
        add_error "no -security APT pocket configured; security classification of updates is unreliable"
    fi
}

ubuntu_compliance_extras() {
    log "running Ubuntu/Debian specific checks"
    ubuntu_check_auto_updates
    ubuntu_check_holds
    ubuntu_check_pro
    ubuntu_check_release_support
    ubuntu_check_dpkg_state
    ubuntu_check_apt_auth
    ubuntu_check_security_pocket
}

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
main() {
    scan_init "$@"
    detect_os

    case "$OS_ID" in
        ubuntu|debian) ;;
        *) add_error "scan_ubuntu.sh executed on '$OS_ID'; results may be incomplete" ;;
    esac

    ubuntu_installed_count
    ubuntu_newest_kernel
    ubuntu_reboot_required

    if want_updates; then
        ubuntu_refresh_cache
        ubuntu_cache_age_note
        ubuntu_collect_updates
    fi

    collect_system

    if want_compliance; then
        run_common_compliance
        ubuntu_compliance_extras
    fi

    scan_finalize
}

main "$@"
