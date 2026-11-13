#!/usr/bin/env bash
# =============================================================================
# scan_common.sh - shared library for the per-distro scan scripts
#
# Sourced by scan_ubuntu.sh / scan_centos.sh / scan_rhel.sh. Provides:
#   * argument parsing            (--scan-id ID --type TYPE --output FILE [--no-refresh])
#   * JSON escaping / emit helpers (pure bash + awk, no jq / python needed)
#   * report state + writer       (always writes valid JSON, even on partial failure)
#   * OS / system information collection
#   * compliance checks common to every distro
#   * helpers shared by the Enterprise Linux family (CentOS/Rocky/Alma/OL/RHEL)
#
# Compatibility: bash 4.2 (CentOS 7), coreutils, awk (gawk or mawk), sed.
# Error handling is explicit - "set -e" is intentionally NOT used.
#
# Report schema (schema_version 1):
#   {"schema_version","scan_id","scan_type","hostname","timestamp",
#    "os":{"id","version","pretty_name","kernel","arch"},
#    "packages":{"installed_count","updates_available","security_updates"},
#    "pending_updates":[{"name","current_version","candidate_version","security","advisory","severity"}],
#    "reboot_required",
#    "compliance":[{"id","title","status","severity","detail"}],
#    "system":{"uptime_seconds","disk":[{"mount","used_percent"}],"memory_mb":{"total","available"},
#              "failed_services":[],"listening_ports":[]},
#    "errors":[]}
# =============================================================================

set -uo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export LC_ALL=C
export LANG=C

# ----------------------------------------------------------------------------
# Global state
# ----------------------------------------------------------------------------
SCAN_SCHEMA_VERSION=1
SCAN_ID=""
SCAN_TYPE="full"
OUTPUT_FILE=""
REFRESH_CACHE=1

ERRORS=()
REPORT_WRITTEN=0
WORK_DIR=""

OS_ID="unknown"
OS_VERSION=""
OS_VERSION_MAJOR=""
OS_PRETTY=""
OS_KERNEL=""
OS_ARCH=""
HOST_NAME=""

PKG_INSTALLED_COUNT=0
REBOOT_REQUIRED="false"
NEWEST_INSTALLED_KERNEL=""

SYS_UPTIME=0
MEM_TOTAL_MB=0
MEM_AVAIL_MB=0

# Work files (TSV), created by scan_init
PENDING_TSV=""       # name \t current \t candidate \t security(true|false) \t advisory \t severity
COMPLIANCE_TSV=""    # id \t title \t status \t severity \t detail
DISK_TSV=""          # mount \t used_percent
FAILED_SVC_FILE=""   # one unit per line
PORTS_FILE=""        # one "port/proto" per line

# Tunables (overridable from the environment)
PM_TIMEOUT="${SCAN_PM_TIMEOUT:-600}"         # seconds for a package manager call
FIND_TIMEOUT="${SCAN_FIND_TIMEOUT:-120}"     # seconds for a filesystem walk

_TAB=$'\t'
_NL=$'\n'
_CR=$'\r'

# ----------------------------------------------------------------------------
# Basic helpers
# ----------------------------------------------------------------------------
log() {
    printf '[%s] %s\n' "$(date -u +%H:%M:%S 2>/dev/null)" "$*" >&2
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# run_to SECONDS cmd [args...] - run an external command with a timeout when
# coreutils "timeout" exists (it does on every supported distro).
run_to() {
    local t="$1"
    shift
    if have timeout; then
        timeout "$t" "$@"
    else
        "$@"
    fi
}

# Flatten a string to a single line without tabs (safe for TSV / error list).
flatten() {
    local s="${1-}"
    s=${s//$_NL/ }
    s=${s//$_CR/ }
    s=${s//$_TAB/ }
    printf '%s' "$s"
}

add_error() {
    local m
    m="$(flatten "$*")"
    # cap very long messages
    if [ "${#m}" -gt 600 ]; then
        m="${m:0:600}..."
    fi
    ERRORS[${#ERRORS[@]}]="$m"
    log "NOTE: $m"
}

# First non-empty line of a file, flattened (for error details).
first_line() {
    local f="$1"
    [ -r "$f" ] || return 0
    awk 'NF { print; exit }' "$f" 2>/dev/null
}

is_uint() {
    [[ "${1-}" =~ ^[0-9]+$ ]]
}

uint_or() {
    # uint_or VALUE DEFAULT
    if is_uint "${1-}"; then printf '%s' "$1"; else printf '%s' "${2:-0}"; fi
}

is_root() {
    [ "$(id -u 2>/dev/null)" = "0" ]
}

svc_active() {
    # svc_active UNIT - true when the systemd unit (or legacy service) is running
    local u="$1"
    if have systemctl; then
        systemctl is-active --quiet "$u" 2>/dev/null
        return $?
    fi
    if have service; then
        service "$u" status >/dev/null 2>&1
        return $?
    fi
    return 1
}

svc_enabled() {
    local u="$1"
    if have systemctl; then
        systemctl is-enabled --quiet "$u" 2>/dev/null
        return $?
    fi
    return 1
}

any_svc_active() {
    # prints the first active unit among the arguments
    local u
    for u in "$@"; do
        if svc_active "$u"; then
            printf '%s' "$u"
            return 0
        fi
    done
    return 1
}

# perm_within ACTUAL MAX - true when octal mode ACTUAL has no bits outside MAX
perm_within() {
    local a="${1-}" m="${2-}"
    [[ "$a" =~ ^[0-7]+$ ]] || return 1
    [[ "$m" =~ ^[0-7]+$ ]] || return 1
    (( ( (8#$a) & ~(8#$m) & 07777 ) == 0 ))
}

# ----------------------------------------------------------------------------
# JSON helpers (awk does the escaping; bash quoting rules differ too much
# between 4.2 and 5.x to do it reliably with parameter expansion)
# ----------------------------------------------------------------------------
# shellcheck disable=SC2016
_AWK_JESC='function jesc(s,   i,c,o,n){o="";n=length(s);for(i=1;i<=n;i++){c=substr(s,i,1);if(c=="\\")o=o "\\\\";else if(c=="\"")o=o "\\\"";else if(c=="\t")o=o "\\t";else if(c<" ")o=o " ";else o=o c}return o}'

# json_escape STRING -> escaped text (without surrounding quotes) on stdout
json_escape() {
    printf '%s' "${1-}" | awk "$_AWK_JESC"' BEGIN{ORS=""} NR>1{print "\\n"} {print jesc($0)}'
}

# json_str STRING -> "escaped"
json_str() {
    printf '"%s"' "$(json_escape "${1-}")"
}

# json_bool VALUE -> true|false
json_bool() {
    case "${1-}" in
        true|TRUE|True|1|yes|YES) printf 'true' ;;
        *) printf 'false' ;;
    esac
}

# json_num VALUE -> integer (0 when not numeric)
json_num() {
    uint_or "${1-}" 0
}

# stdin: one string per line -> JSON array of strings
json_lines_to_array() {
    awk "$_AWK_JESC"' BEGIN{printf "["} length($0)>0 { if(n++) printf ","; printf "\"%s\"", jesc($0) } END{printf "]"}'
}

# json_array_from_args a b c -> ["a","b","c"]
json_array_from_args() {
    if [ $# -eq 0 ]; then
        printf '[]'
        return 0
    fi
    printf '%s\n' "$@" | json_lines_to_array
}

_emit_errors_json() {
    if [ "${#ERRORS[@]}" -eq 0 ]; then
        printf '[]'
    else
        printf '%s\n' "${ERRORS[@]}" | json_lines_to_array
    fi
}

_emit_pending_json() {
    if [ -s "$PENDING_TSV" ]; then
        awk -F'\t' "$_AWK_JESC"'
            BEGIN { printf "[" }
            NF >= 3 && length($1) > 0 {
                if (n++) printf ","
                sec = ($4 == "true") ? "true" : "false"
                sev = $6
                if (sev !~ /^(critical|important|moderate|low)$/) sev = "unknown"
                printf "{\"name\":\"%s\",\"current_version\":\"%s\",\"candidate_version\":\"%s\",\"security\":%s,\"advisory\":\"%s\",\"severity\":\"%s\"}", jesc($1), jesc($2), jesc($3), sec, jesc($5), sev
            }
            END { printf "]" }' "$PENDING_TSV"
    else
        printf '[]'
    fi
}

_emit_compliance_json() {
    if [ -s "$COMPLIANCE_TSV" ]; then
        awk -F'\t' "$_AWK_JESC"'
            BEGIN { printf "[" }
            NF >= 4 && length($1) > 0 {
                if (n++) printf ","
                st = $3; if (st !~ /^(pass|fail|warn|skip)$/) st = "skip"
                sv = $4; if (sv !~ /^(high|medium|low)$/) sv = "low"
                printf "{\"id\":\"%s\",\"title\":\"%s\",\"status\":\"%s\",\"severity\":\"%s\",\"detail\":\"%s\"}", jesc($1), jesc($2), st, sv, jesc($5)
            }
            END { printf "]" }' "$COMPLIANCE_TSV"
    else
        printf '[]'
    fi
}

_emit_disk_json() {
    if [ -s "$DISK_TSV" ]; then
        awk -F'\t' "$_AWK_JESC"'
            BEGIN { printf "[" }
            NF >= 2 && $2 ~ /^[0-9]+$/ {
                if (n++) printf ","
                printf "{\"mount\":\"%s\",\"used_percent\":%d}", jesc($1), $2
            }
            END { printf "]" }' "$DISK_TSV"
    else
        printf '[]'
    fi
}

_emit_lines_file_json() {
    local f="$1"
    if [ -s "$f" ]; then
        json_lines_to_array < "$f"
    else
        printf '[]'
    fi
}

_count_pending() {
    # _count_pending all|security
    local what="$1"
    [ -s "$PENDING_TSV" ] || { printf '0'; return 0; }
    if [ "$what" = "security" ]; then
        awk -F'\t' 'NF>=3 && length($1)>0 && $4=="true" {n++} END{print n+0}' "$PENDING_TSV"
    else
        awk -F'\t' 'NF>=3 && length($1)>0 {n++} END{print n+0}' "$PENDING_TSV"
    fi
}

# ----------------------------------------------------------------------------
# Report writer
# ----------------------------------------------------------------------------
write_report() {
    local tmp="${OUTPUT_FILE}.tmp.$$" outdir upd sec ts
    outdir="$(dirname "$OUTPUT_FILE")"
    if [ ! -d "$outdir" ]; then
        mkdir -p "$outdir" 2>/dev/null || true
    fi
    upd="$(_count_pending all)"
    sec="$(_count_pending security)"
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
    [ -n "$HOST_NAME" ] || HOST_NAME="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)"

    {
        printf '{'
        printf '"schema_version":%d,' "$SCAN_SCHEMA_VERSION"
        printf '"scan_id":%s,' "$(json_str "$SCAN_ID")"
        printf '"scan_type":%s,' "$(json_str "$SCAN_TYPE")"
        printf '"hostname":%s,' "$(json_str "$HOST_NAME")"
        printf '"timestamp":%s,' "$(json_str "$ts")"
        printf '"os":{"id":%s,"version":%s,"pretty_name":%s,"kernel":%s,"arch":%s},' \
            "$(json_str "$OS_ID")" "$(json_str "$OS_VERSION")" "$(json_str "$OS_PRETTY")" \
            "$(json_str "$OS_KERNEL")" "$(json_str "$OS_ARCH")"
        printf '"packages":{"installed_count":%s,"updates_available":%s,"security_updates":%s},' \
            "$(json_num "$PKG_INSTALLED_COUNT")" "$(json_num "$upd")" "$(json_num "$sec")"
        printf '"pending_updates":'
        _emit_pending_json
        printf ','
        printf '"reboot_required":%s,' "$(json_bool "$REBOOT_REQUIRED")"
        printf '"compliance":'
        _emit_compliance_json
        printf ','
        printf '"system":{"uptime_seconds":%s,"disk":' "$(json_num "$SYS_UPTIME")"
        _emit_disk_json
        printf ',"memory_mb":{"total":%s,"available":%s},' "$(json_num "$MEM_TOTAL_MB")" "$(json_num "$MEM_AVAIL_MB")"
        printf '"failed_services":'
        _emit_lines_file_json "$FAILED_SVC_FILE"
        printf ',"listening_ports":'
        _emit_lines_file_json "$PORTS_FILE"
        printf '},'
        printf '"errors":'
        _emit_errors_json
        printf '}\n'
    } > "$tmp" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }

    # Drop any byte sequences that are not valid UTF-8 (package descriptions,
    # odd file names ...) so that strict JSON parsers do not choke.
    if have iconv; then
        if iconv -f UTF-8 -t UTF-8 -c "$tmp" > "${tmp}.u8" 2>/dev/null && [ -s "${tmp}.u8" ]; then
            mv -f "${tmp}.u8" "$tmp" 2>/dev/null || true
        else
            rm -f "${tmp}.u8" 2>/dev/null
        fi
    fi

    if mv -f "$tmp" "$OUTPUT_FILE" 2>/dev/null; then
        chmod 0644 "$OUTPUT_FILE" 2>/dev/null || true
        REPORT_WRITTEN=1
        return 0
    fi
    rm -f "$tmp" 2>/dev/null
    return 1
}

# Called by the distro script as the very last step.
scan_finalize() {
    if write_report; then
        log "report written to $OUTPUT_FILE"
        _scan_cleanup
        trap - EXIT
        exit 0
    fi
    echo "FATAL: could not write report to $OUTPUT_FILE" >&2
    _scan_cleanup
    trap - EXIT
    exit 3
}

_scan_cleanup() {
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR" 2>/dev/null || true
    fi
}

_scan_on_exit() {
    local rc=$?
    if [ "$REPORT_WRITTEN" -eq 0 ] && [ -n "$OUTPUT_FILE" ]; then
        add_error "scan terminated before completion (exit code $rc); report is partial"
        if write_report; then
            rc=0
        else
            echo "FATAL: could not write report to $OUTPUT_FILE" >&2
            rc=3
        fi
    fi
    _scan_cleanup
    exit "$rc"
}

_scan_on_signal() {
    add_error "scan interrupted by signal $1; report is partial"
    exit 0   # the EXIT trap writes the report
}

# ----------------------------------------------------------------------------
# Argument parsing / initialisation
# ----------------------------------------------------------------------------
scan_usage() {
    cat >&2 <<'EOF'
Usage: scan_<distro>.sh --scan-id ID --type TYPE --output FILE [--no-refresh]
  --scan-id ID     identifier echoed back in the report
  --type TYPE      full | vulnerability | compliance | inventory   (default: full)
  --output FILE    where the JSON report is written
  --no-refresh     do not refresh package manager metadata first
EOF
}

scan_parse_args() {
    local unknown=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --scan-id)   SCAN_ID="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --scan-id=*) SCAN_ID="${1#*=}"; shift ;;
            --type)      SCAN_TYPE="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --type=*)    SCAN_TYPE="${1#*=}"; shift ;;
            --output)    OUTPUT_FILE="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --output=*)  OUTPUT_FILE="${1#*=}"; shift ;;
            --no-refresh) REFRESH_CACHE=0; shift ;;
            --refresh)   REFRESH_CACHE=1; shift ;;
            -h|--help)   scan_usage; exit 0 ;;
            *)           unknown="$unknown $1"; shift ;;
        esac
    done

    if [ -z "$OUTPUT_FILE" ]; then
        echo "FATAL: --output FILE is required" >&2
        scan_usage
        exit 2
    fi

    case "$SCAN_TYPE" in
        full|vulnerability|compliance|inventory) ;;
        "") SCAN_TYPE="full" ;;
        *)
            local bad="$SCAN_TYPE"
            SCAN_TYPE="full"
            add_error "unknown scan type '$bad', falling back to 'full'"
            ;;
    esac

    [ -n "$unknown" ] && add_error "ignored unknown arguments:$unknown"
    [ -n "$SCAN_ID" ] || add_error "no --scan-id supplied"
    return 0
}

scan_init() {
    scan_parse_args "$@"

    trap '_scan_on_exit' EXIT
    trap '_scan_on_signal TERM' TERM
    trap '_scan_on_signal INT' INT
    trap '_scan_on_signal HUP' HUP

    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/provscan.XXXXXX" 2>/dev/null)"
    if [ -z "$WORK_DIR" ] || [ ! -d "$WORK_DIR" ]; then
        WORK_DIR="/tmp/provscan.$$"
        mkdir -p "$WORK_DIR" 2>/dev/null || true
    fi
    chmod 0700 "$WORK_DIR" 2>/dev/null || true

    PENDING_TSV="$WORK_DIR/pending.tsv"
    COMPLIANCE_TSV="$WORK_DIR/compliance.tsv"
    DISK_TSV="$WORK_DIR/disk.tsv"
    FAILED_SVC_FILE="$WORK_DIR/failed_services.txt"
    PORTS_FILE="$WORK_DIR/ports.txt"
    : > "$PENDING_TSV" 2>/dev/null
    : > "$COMPLIANCE_TSV" 2>/dev/null
    : > "$DISK_TSV" 2>/dev/null
    : > "$FAILED_SVC_FILE" 2>/dev/null
    : > "$PORTS_FILE" 2>/dev/null

    if ! is_root; then
        add_error "scan is not running as root; some checks will be incomplete"
    fi
    log "scan start id=$SCAN_ID type=$SCAN_TYPE output=$OUTPUT_FILE refresh=$REFRESH_CACHE"
}

# Which sections does the requested scan type include?
want_updates() {
    case "$SCAN_TYPE" in full|vulnerability) return 0 ;; esac
    return 1
}

want_compliance() {
    case "$SCAN_TYPE" in full|compliance) return 0 ;; esac
    return 1
}

want_system() {
    # system information is cheap - always collected; kept as a hook
    return 0
}

# ----------------------------------------------------------------------------
# Pending update / compliance record helpers
# ----------------------------------------------------------------------------
# add_pending NAME CURRENT CANDIDATE SECURITY ADVISORY SEVERITY
add_pending() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(flatten "${1-}")" "$(flatten "${2-}")" "$(flatten "${3-}")" \
        "$(json_bool "${4-false}")" "$(flatten "${5-}")" "$(flatten "${6-unknown}")" >> "$PENDING_TSV"
}

# add_check ID TITLE STATUS SEVERITY DETAIL
add_check() {
    local d
    d="$(flatten "${5-}")"
    if [ "${#d}" -gt 500 ]; then
        d="${d:0:500}..."
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(flatten "${1-}")" "$(flatten "${2-}")" "${3-skip}" "${4-low}" "$d" >> "$COMPLIANCE_TSV"
}

# ----------------------------------------------------------------------------
# OS detection
# ----------------------------------------------------------------------------
os_release_get() {
    # os_release_get KEY [FILE]
    local key="$1" file="${2:-/etc/os-release}"
    [ -r "$file" ] || return 0
    awk -F= -v k="$key" '$1 == k { v = $0; sub(/^[^=]*=/, "", v); gsub(/^[\042\047]|[\042\047]$/, "", v); print v; exit }' "$file" 2>/dev/null
}

detect_os() {
    local f=""
    if [ -r /etc/os-release ]; then
        f=/etc/os-release
    elif [ -r /usr/lib/os-release ]; then
        f=/usr/lib/os-release
    fi

    if [ -n "$f" ]; then
        OS_ID="$(os_release_get ID "$f")"
        OS_VERSION="$(os_release_get VERSION_ID "$f")"
        OS_PRETTY="$(os_release_get PRETTY_NAME "$f")"
    fi

    # Legacy fallbacks (EL6 and friends have no os-release)
    if [ -z "$OS_ID" ] || [ "$OS_ID" = "unknown" ]; then
        if [ -r /etc/centos-release ]; then
            OS_ID="centos"
            OS_PRETTY="$(head -n1 /etc/centos-release 2>/dev/null)"
        elif [ -r /etc/oracle-release ]; then
            OS_ID="ol"
            OS_PRETTY="$(head -n1 /etc/oracle-release 2>/dev/null)"
        elif [ -r /etc/redhat-release ]; then
            OS_ID="rhel"
            OS_PRETTY="$(head -n1 /etc/redhat-release 2>/dev/null)"
        elif [ -r /etc/debian_version ]; then
            OS_ID="debian"
            OS_VERSION="$(head -n1 /etc/debian_version 2>/dev/null)"
            OS_PRETTY="Debian $OS_VERSION"
        elif have lsb_release; then
            OS_ID="$(lsb_release -si 2>/dev/null | tr '[:upper:]' '[:lower:]')"
            OS_VERSION="$(lsb_release -sr 2>/dev/null)"
            OS_PRETTY="$(lsb_release -sd 2>/dev/null)"
        fi
    fi
    if [ -z "$OS_VERSION" ] && [ -n "$OS_PRETTY" ]; then
        OS_VERSION="$(printf '%s' "$OS_PRETTY" | sed -n 's/[^0-9]*\([0-9][0-9.]*\).*/\1/p' | head -n1)"
    fi
    # CentOS 7 reports VERSION_ID="7"; refine from centos-release (7.9.2009)
    if [ -r /etc/centos-release ] && [[ "$OS_VERSION" =~ ^[0-9]+$ ]]; then
        local full
        full="$(sed -n 's/[^0-9]*\([0-9][0-9]*\.[0-9][0-9.]*\).*/\1/p' /etc/centos-release 2>/dev/null | head -n1)"
        [ -n "$full" ] && OS_VERSION="$full"
    fi

    [ -n "$OS_ID" ] || OS_ID="unknown"
    OS_ID="$(printf '%s' "$OS_ID" | tr '[:upper:]' '[:lower:]')"
    OS_VERSION_MAJOR="${OS_VERSION%%.*}"
    [ -n "$OS_PRETTY" ] || OS_PRETTY="$OS_ID $OS_VERSION"
    OS_KERNEL="$(uname -r 2>/dev/null)"
    OS_ARCH="$(uname -m 2>/dev/null)"
    HOST_NAME="$(hostname -f 2>/dev/null)"
    if [ -z "$HOST_NAME" ] || [ "$HOST_NAME" = "localhost" ]; then
        HOST_NAME="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)"
    fi
    log "detected os id=$OS_ID version=$OS_VERSION kernel=$OS_KERNEL arch=$OS_ARCH"
}

# True when the host looks like a container (no own kernel, no systemd PID 1 ...)
is_container() {
    if have systemd-detect-virt && systemd-detect-virt --container --quiet 2>/dev/null; then
        return 0
    fi
    [ -f /.dockerenv ] && return 0
    [ -f /run/.containerenv ] && return 0
    grep -qaE '(docker|lxc|kubepods|containerd)' /proc/1/cgroup 2>/dev/null && return 0
    return 1
}

# ----------------------------------------------------------------------------
# System information
# ----------------------------------------------------------------------------
collect_uptime() {
    if [ -r /proc/uptime ]; then
        SYS_UPTIME="$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null)"
    fi
    SYS_UPTIME="$(uint_or "$SYS_UPTIME" 0)"
}

collect_disk() {
    # Real filesystems only; pseudo / overlay / squashfs (snap) mounts are noise.
    local out
    out="$(run_to 30 df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs -x iso9660 -x fuse.lxcfs 2>/dev/null)"
    if [ -z "$out" ]; then
        out="$(run_to 30 df -P -k 2>/dev/null)"
    fi
    if [ -z "$out" ]; then
        add_error "df failed or timed out (stale network mount?); disk usage not collected"
        return 0
    fi
    printf '%s\n' "$out" | awk -v OFS='\t' '
        NR > 1 && NF >= 6 {
            pct = $5; gsub(/%/, "", pct)
            if (pct !~ /^[0-9]+$/) next
            mnt = $6
            for (i = 7; i <= NF; i++) mnt = mnt " " $i
            if (mnt ~ /^\/(proc|sys|dev|run)(\/|$)/) next
            if (mnt ~ /^\/snap\// || mnt ~ /^\/var\/lib\/(docker|containers|kubelet)\//) next
            if (!(mnt in seen)) { seen[mnt] = 1; print mnt, pct }
        }' > "$DISK_TSV" 2>/dev/null
}

collect_memory() {
    if [ -r /proc/meminfo ]; then
        local vals
        vals="$(awk '
            /^MemTotal:/     { t = $2 }
            /^MemAvailable:/ { a = $2; hasa = 1 }
            /^MemFree:/      { f = $2 }
            /^Buffers:/      { b = $2 }
            /^Cached:/       { c = $2 }
            END {
                if (!hasa) a = f + b + c
                printf "%d %d", t / 1024, a / 1024
            }' /proc/meminfo 2>/dev/null)"
        MEM_TOTAL_MB="$(uint_or "${vals%% *}" 0)"
        MEM_AVAIL_MB="$(uint_or "${vals##* }" 0)"
    else
        add_error "/proc/meminfo not readable; memory figures unavailable"
    fi
}

collect_failed_services() {
    if ! have systemctl; then
        return 0
    fi
    if [ ! -d /run/systemd/system ]; then
        # systemd not PID 1 (container / chroot)
        return 0
    fi
    run_to 30 systemctl list-units --state=failed --no-legend --plain --no-pager 2>/dev/null \
        | awk '{ u = $1; if (u !~ /\./ && NF > 1) u = $2; if (u ~ /\./) print u }' \
        | sort -u > "$FAILED_SVC_FILE" 2>/dev/null
}

collect_listening_ports() {
    if have ss; then
        run_to 30 ss -tuln 2>/dev/null | awk '
            NR > 1 {
                if ($1 ~ /^tcp/) p = "tcp"; else if ($1 ~ /^udp/) p = "udp"; else next
                if (p == "tcp" && $2 != "LISTEN") next
                n = split($5, a, ":"); port = a[n]
                if (port ~ /^[0-9]+$/) print port "/" p
            }' | sort -t/ -k1,1n -k2,2 -u > "$PORTS_FILE" 2>/dev/null
    elif have netstat; then
        run_to 30 netstat -tuln 2>/dev/null | awk '
            /^(tcp|udp)/ {
                p = ($1 ~ /^tcp/) ? "tcp" : "udp"
                if (p == "tcp" && $NF != "LISTEN") next
                n = split($4, a, ":"); port = a[n]
                if (port ~ /^[0-9]+$/) print port "/" p
            }' | sort -t/ -k1,1n -k2,2 -u > "$PORTS_FILE" 2>/dev/null
    else
        add_error "neither ss nor netstat available; listening ports not collected"
    fi
}

collect_system() {
    log "collecting system information"
    collect_uptime
    collect_disk
    collect_memory
    collect_failed_services
    collect_listening_ports
}

port_listening() {
    # port_listening 23/tcp
    [ -s "$PORTS_FILE" ] && grep -qx "$1" "$PORTS_FILE" 2>/dev/null
}

# ----------------------------------------------------------------------------
# SSH daemon configuration access
# ----------------------------------------------------------------------------
SSHD_EFFECTIVE=""       # file with "key value" lines, keys lower-cased
SSHD_SOURCE="none"      # sshd-T | parsed | none

_sshd_prepare() {
    [ -n "$SSHD_EFFECTIVE" ] && return 0
    SSHD_EFFECTIVE="$WORK_DIR/sshd_effective.txt"
    : > "$SSHD_EFFECTIVE"

    local bin=""
    if have sshd; then
        bin="$(command -v sshd)"
    elif [ -x /usr/sbin/sshd ]; then
        bin=/usr/sbin/sshd
    fi

    if [ -n "$bin" ] && is_root; then
        if run_to 20 "$bin" -T > "$SSHD_EFFECTIVE" 2>/dev/null && [ -s "$SSHD_EFFECTIVE" ]; then
            SSHD_SOURCE="sshd-T"
            return 0
        fi
        : > "$SSHD_EFFECTIVE"
    fi

    if [ -r /etc/ssh/sshd_config ]; then
        # Best effort parse: global section only (stop at the first Match block),
        # first occurrence of a keyword wins, drop-in directory honoured when an
        # Include directive is present.
        local files=()
        if grep -qiE '^[[:space:]]*Include[[:space:]]' /etc/ssh/sshd_config 2>/dev/null; then
            local d
            for d in /etc/ssh/sshd_config.d/*.conf; do
                [ -r "$d" ] && files[${#files[@]}]="$d"
            done
        fi
        files[${#files[@]}]=/etc/ssh/sshd_config
        awk '
            FNR == 1 { inmatch = 0 }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*$/ { next }
            {
                line = $0
                sub(/^[[:space:]]+/, "", line)
                sub(/[[:space:]]+$/, "", line)
                n = index(line, " "); t = index(line, "\t"); e = index(line, "=")
                p = 0
                if (n > 0) p = n
                if (t > 0 && (p == 0 || t < p)) p = t
                if (e > 0 && (p == 0 || e < p)) p = e
                if (p == 0) next
                k = tolower(substr(line, 1, p - 1))
                v = substr(line, p + 1)
                sub(/^[[:space:]=]+/, "", v)
                gsub(/"/, "", v)
                if (k == "match") { inmatch = 1; next }
                if (inmatch) next
                if (!(k in seen)) { seen[k] = 1; print k " " v }
            }' "${files[@]}" > "$SSHD_EFFECTIVE" 2>/dev/null
        if [ -s "$SSHD_EFFECTIVE" ]; then
            SSHD_SOURCE="parsed"
        fi
        # an existing but effectively empty config still counts as parsed
        [ "$SSHD_SOURCE" = "none" ] && SSHD_SOURCE="parsed"
    fi
    return 0
}

# sshd_get KEY [DEFAULT] - effective value (lower-cased), DEFAULT when unset
sshd_get() {
    local key="$1" def="${2-}" v
    _sshd_prepare
    v="$(awk -v k="$key" '$1 == k { $1 = ""; sub(/^ /, ""); print tolower($0); exit }' "$SSHD_EFFECTIVE" 2>/dev/null)"
    if [ -n "$v" ]; then
        printf '%s' "$v"
    else
        printf '%s' "$def"
    fi
}

# ----------------------------------------------------------------------------
# Compliance checks - SSH
# ----------------------------------------------------------------------------
check_ssh() {
    _sshd_prepare
    if [ "$SSHD_SOURCE" = "none" ]; then
        local id
        for id in "SSH-001:SSH root login disabled" "SSH-002:SSH password authentication disabled" \
                  "SSH-003:SSH empty passwords disallowed" "SSH-004:SSH protocol 2 only" \
                  "SSH-005:SSH weak ciphers/MACs/KEX disabled" "SSH-006:SSH MaxAuthTries limited" \
                  "SSH-007:SSH X11 forwarding disabled" "SSH-008:SSH idle timeout configured" \
                  "SSH-009:SSH configuration file permissions"; do
            add_check "${id%%:*}" "${id#*:}" skip low "OpenSSH server not installed or configuration not readable"
        done
        return 0
    fi
    local src="source: $SSHD_SOURCE" v

    # SSH-001 root login
    v="$(sshd_get permitrootlogin "")"
    case "$v" in
        no) add_check SSH-001 "SSH root login disabled" pass high "PermitRootLogin no ($src)" ;;
        prohibit-password|without-password|forced-commands-only)
            add_check SSH-001 "SSH root login disabled" warn high "PermitRootLogin $v - key based root login still possible ($src)" ;;
        yes) add_check SSH-001 "SSH root login disabled" fail high "PermitRootLogin yes ($src)" ;;
        "")  add_check SSH-001 "SSH root login disabled" warn high "PermitRootLogin not set explicitly; compiled-in default applies ($src)" ;;
        *)   add_check SSH-001 "SSH root login disabled" warn high "PermitRootLogin has unexpected value '$v' ($src)" ;;
    esac

    # SSH-002 password authentication
    v="$(sshd_get passwordauthentication "")"
    case "$v" in
        no)  add_check SSH-002 "SSH password authentication disabled" pass medium "PasswordAuthentication no ($src)" ;;
        yes) add_check SSH-002 "SSH password authentication disabled" fail medium "PasswordAuthentication yes ($src)" ;;
        "")  add_check SSH-002 "SSH password authentication disabled" fail medium "PasswordAuthentication not set; OpenSSH default is yes ($src)" ;;
        *)   add_check SSH-002 "SSH password authentication disabled" warn medium "PasswordAuthentication '$v' ($src)" ;;
    esac

    # SSH-003 empty passwords
    v="$(sshd_get permitemptypasswords "no")"
    if [ "$v" = "no" ]; then
        add_check SSH-003 "SSH empty passwords disallowed" pass high "PermitEmptyPasswords no ($src)"
    else
        add_check SSH-003 "SSH empty passwords disallowed" fail high "PermitEmptyPasswords $v ($src)"
    fi

    # SSH-004 protocol
    local proto=""
    proto="$(grep -ihE '^[[:space:]]*Protocol[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2; exit}')"
    if [ -z "$proto" ]; then
        add_check SSH-004 "SSH protocol 2 only" pass high "no Protocol directive; OpenSSH 7.4+ supports protocol 2 only"
    elif [ "$proto" = "2" ]; then
        add_check SSH-004 "SSH protocol 2 only" pass high "Protocol 2"
    else
        add_check SSH-004 "SSH protocol 2 only" fail high "Protocol $proto configured - legacy protocol 1 must not be enabled"
    fi

    # SSH-005 weak crypto
    local ciphers macs kex weak=""
    ciphers="$(sshd_get ciphers "")"
    macs="$(sshd_get macs "")"
    kex="$(sshd_get kexalgorithms "")"
    local item
    for item in $(printf '%s' "$ciphers" | tr ',' ' '); do
        case "$item" in
            3des-cbc|arcfour*|blowfish-cbc|cast128-cbc|aes128-cbc|aes192-cbc|aes256-cbc|rijndael-cbc*)
                weak="$weak cipher:$item" ;;
        esac
    done
    for item in $(printf '%s' "$macs" | tr ',' ' '); do
        case "$item" in
            hmac-md5*|hmac-sha1-96*|umac-64*|hmac-ripemd160*)
                weak="$weak mac:$item" ;;
        esac
    done
    for item in $(printf '%s' "$kex" | tr ',' ' '); do
        case "$item" in
            diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1|diffie-hellman-group14-sha1)
                weak="$weak kex:$item" ;;
        esac
    done
    if [ -z "$ciphers$macs$kex" ]; then
        add_check SSH-005 "SSH weak ciphers/MACs/KEX disabled" warn medium "effective algorithm lists unavailable ($src); compiled-in defaults apply"
    elif [ -n "$weak" ]; then
        add_check SSH-005 "SSH weak ciphers/MACs/KEX disabled" fail medium "weak algorithms enabled:$weak"
    else
        add_check SSH-005 "SSH weak ciphers/MACs/KEX disabled" pass medium "no weak ciphers, MACs or key exchange algorithms enabled ($src)"
    fi

    # SSH-006 MaxAuthTries
    v="$(sshd_get maxauthtries "6")"
    if is_uint "$v" && [ "$v" -le 4 ]; then
        add_check SSH-006 "SSH MaxAuthTries limited" pass low "MaxAuthTries $v"
    else
        add_check SSH-006 "SSH MaxAuthTries limited" warn low "MaxAuthTries $v (recommended: 4 or less)"
    fi

    # SSH-007 X11 forwarding
    v="$(sshd_get x11forwarding "no")"
    if [ "$v" = "no" ]; then
        add_check SSH-007 "SSH X11 forwarding disabled" pass low "X11Forwarding no"
    else
        add_check SSH-007 "SSH X11 forwarding disabled" warn low "X11Forwarding $v"
    fi

    # SSH-008 idle timeout
    local cai cac
    cai="$(sshd_get clientaliveinterval "0")"
    cac="$(sshd_get clientalivecountmax "3")"
    if is_uint "$cai" && [ "$cai" -gt 0 ] && [ "$cai" -le 900 ]; then
        add_check SSH-008 "SSH idle timeout configured" pass low "ClientAliveInterval $cai, ClientAliveCountMax $cac"
    else
        add_check SSH-008 "SSH idle timeout configured" warn low "ClientAliveInterval $cai (recommended: 1-900 seconds)"
    fi

    # SSH-009 file permissions
    local bad="" mode owner f
    if [ -e /etc/ssh/sshd_config ]; then
        mode="$(stat -c '%a' /etc/ssh/sshd_config 2>/dev/null)"
        owner="$(stat -c '%U' /etc/ssh/sshd_config 2>/dev/null)"
        if ! perm_within "$mode" 644 || [ "$owner" != "root" ]; then
            bad="$bad sshd_config($owner:$mode)"
        fi
    fi
    for f in /etc/ssh/ssh_host_*_key; do
        [ -e "$f" ] || continue
        mode="$(stat -c '%a' "$f" 2>/dev/null)"
        # EL uses 640 root:ssh_keys for host keys - accept that
        if ! perm_within "$mode" 640; then
            bad="$bad ${f##*/}($mode)"
        fi
    done
    if [ -z "$bad" ]; then
        add_check SSH-009 "SSH configuration file permissions" pass medium "sshd_config and private host keys are not group/world accessible beyond policy"
    else
        add_check SSH-009 "SSH configuration file permissions" fail medium "overly permissive:$bad"
    fi
}

# ----------------------------------------------------------------------------
# Compliance checks - accounts / authentication
# ----------------------------------------------------------------------------
login_defs_get() {
    [ -r /etc/login.defs ] || return 0
    awk -v k="$1" '$1 == k { print $2; exit }' /etc/login.defs 2>/dev/null
}

check_accounts() {
    local v

    # AUTH-001..003 password ageing
    if [ ! -r /etc/login.defs ]; then
        add_check AUTH-001 "Password maximum age" skip medium "/etc/login.defs not readable"
        add_check AUTH-002 "Password minimum age" skip low "/etc/login.defs not readable"
        add_check AUTH-003 "Password expiry warning" skip low "/etc/login.defs not readable"
    else
        v="$(login_defs_get PASS_MAX_DAYS)"
        if is_uint "$v" && [ "$v" -ge 1 ] && [ "$v" -le 365 ]; then
            add_check AUTH-001 "Password maximum age" pass medium "PASS_MAX_DAYS $v"
        else
            add_check AUTH-001 "Password maximum age" fail medium "PASS_MAX_DAYS ${v:-unset} (expected 1-365)"
        fi
        v="$(login_defs_get PASS_MIN_DAYS)"
        if is_uint "$v" && [ "$v" -ge 1 ]; then
            add_check AUTH-002 "Password minimum age" pass low "PASS_MIN_DAYS $v"
        else
            add_check AUTH-002 "Password minimum age" warn low "PASS_MIN_DAYS ${v:-unset} (expected 1 or more)"
        fi
        v="$(login_defs_get PASS_WARN_AGE)"
        if is_uint "$v" && [ "$v" -ge 7 ]; then
            add_check AUTH-003 "Password expiry warning" pass low "PASS_WARN_AGE $v"
        else
            add_check AUTH-003 "Password expiry warning" warn low "PASS_WARN_AGE ${v:-unset} (expected 7 or more)"
        fi
    fi

    # AUTH-004 accounts with empty password
    if [ -r /etc/shadow ]; then
        local empties
        empties="$(awk -F: '$2 == "" { printf "%s ", $1 }' /etc/shadow 2>/dev/null)"
        if [ -z "$empties" ]; then
            add_check AUTH-004 "No accounts with empty passwords" pass high "no empty password fields in /etc/shadow"
        else
            add_check AUTH-004 "No accounts with empty passwords" fail high "accounts with empty password: $empties"
        fi
    else
        add_check AUTH-004 "No accounts with empty passwords" skip high "/etc/shadow not readable (not root?)"
    fi

    # AUTH-005 UID 0 accounts
    if [ -r /etc/passwd ]; then
        local uid0
        uid0="$(awk -F: '$3 == 0 && $1 != "root" { printf "%s ", $1 }' /etc/passwd 2>/dev/null)"
        if [ -z "$uid0" ]; then
            add_check AUTH-005 "Only root has UID 0" pass high "root is the only UID 0 account"
        else
            add_check AUTH-005 "Only root has UID 0" fail high "additional UID 0 accounts: $uid0"
        fi
    else
        add_check AUTH-005 "Only root has UID 0" skip high "/etc/passwd not readable"
    fi

    # AUTH-006 sudoers NOPASSWD
    if [ -r /etc/sudoers ] || [ -d /etc/sudoers.d ]; then
        local hits cnt
        hits="$(grep -rhsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null)"
        if [ -z "$hits" ]; then
            add_check AUTH-006 "sudo requires a password (no NOPASSWD)" pass medium "no NOPASSWD entries in sudoers"
        else
            cnt="$(printf '%s\n' "$hits" | wc -l | tr -d ' ')"
            local who
            who="$(printf '%s\n' "$hits" | awk '{print $1}' | sort -u | head -n 8 | tr '\n' ' ')"
            add_check AUTH-006 "sudo requires a password (no NOPASSWD)" warn medium "$cnt NOPASSWD entr(y/ies) for: $who"
        fi
    else
        add_check AUTH-006 "sudo requires a password (no NOPASSWD)" skip medium "sudoers not readable or sudo not installed"
    fi

    # AUTH-007 permissions on account databases
    local bad="" spec f max mode owner
    for spec in "/etc/passwd:644" "/etc/group:644" "/etc/shadow:640" "/etc/gshadow:640" \
                "/etc/passwd-:644" "/etc/shadow-:640"; do
        f="${spec%%:*}"
        max="${spec##*:}"
        [ -e "$f" ] || continue
        mode="$(stat -c '%a' "$f" 2>/dev/null)"
        owner="$(stat -c '%U' "$f" 2>/dev/null)"
        if ! perm_within "$mode" "$max" || [ "$owner" != "root" ]; then
            bad="$bad $f($owner:$mode,max $max)"
        fi
    done
    if [ -z "$bad" ]; then
        add_check AUTH-007 "Account database file permissions" pass high "passwd/shadow/group/gshadow ownership and modes are correct"
    else
        add_check AUTH-007 "Account database file permissions" fail high "incorrect:$bad"
    fi

    # AUTH-008 password quality module
    if [ -d /etc/pam.d ]; then
        if grep -rqsE '^[^#]*pam_(pwquality|cracklib|passwdqc)\.so' /etc/pam.d 2>/dev/null; then
            local minlen=""
            [ -r /etc/security/pwquality.conf ] && minlen="$(awk -F= '/^[[:space:]]*minlen/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' /etc/security/pwquality.conf 2>/dev/null)"
            add_check AUTH-008 "Password quality enforcement (PAM)" pass medium "pam_pwquality/cracklib configured${minlen:+, minlen=$minlen}"
        else
            add_check AUTH-008 "Password quality enforcement (PAM)" warn medium "no pam_pwquality / pam_cracklib / pam_passwdqc module in /etc/pam.d"
        fi
    else
        add_check AUTH-008 "Password quality enforcement (PAM)" skip medium "/etc/pam.d not present"
    fi

    # AUTH-009 account lockout
    if [ -d /etc/pam.d ]; then
        if grep -rqsE '^[^#]*pam_(faillock|tally2|tally)\.so' /etc/pam.d 2>/dev/null; then
            add_check AUTH-009 "Account lockout on failed logins" pass medium "pam_faillock/pam_tally configured"
        else
            add_check AUTH-009 "Account lockout on failed logins" warn medium "no pam_faillock / pam_tally2 configuration found"
        fi
    else
        add_check AUTH-009 "Account lockout on failed logins" skip medium "/etc/pam.d not present"
    fi
}

# ----------------------------------------------------------------------------
# Compliance checks - filesystem
# ----------------------------------------------------------------------------
# Directories pruned from whole-filesystem walks (container layers, pseudo fs).
_FIND_PRUNE=( '(' -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap
              -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/containerd
              -o -path /var/lib/kubelet -o -path /var/lib/lxd -o -path /var/lib/lxcfs
              -o -path /var/snap ')' -prune -o )

mount_opts() {
    # mount_opts /tmp -> comma separated options when /tmp is its own mount point
    local mp="$1"
    if have findmnt; then
        findmnt -n -o OPTIONS --target "$mp" --mountpoint "$mp" 2>/dev/null | head -n1 && return 0
    fi
    awk -v m="$mp" '$2 == m { o = $4 } END { if (o != "") print o }' /proc/mounts 2>/dev/null
}

is_mountpoint() {
    local mp="$1"
    if have mountpoint; then
        mountpoint -q "$mp" 2>/dev/null
        return $?
    fi
    awk -v m="$mp" '$2 == m { f = 1 } END { exit f ? 0 : 1 }' /proc/mounts 2>/dev/null
}

_check_mount_hardening() {
    # _check_mount_hardening ID TITLE MOUNTPOINT SEVERITY
    local id="$1" title="$2" mp="$3" sev="$4" opts missing="" o
    if [ ! -d "$mp" ]; then
        add_check "$id" "$title" skip "$sev" "$mp does not exist"
        return 0
    fi
    if ! is_mountpoint "$mp"; then
        add_check "$id" "$title" warn "$sev" "$mp is not a separate mount; nodev/nosuid/noexec cannot be enforced"
        return 0
    fi
    opts="$(awk -v m="$mp" '$2 == m { o = $4 } END { print o }' /proc/mounts 2>/dev/null)"
    for o in nodev nosuid noexec; do
        case ",$opts," in
            *",$o,"*) ;;
            *) missing="$missing $o" ;;
        esac
    done
    if [ -z "$missing" ]; then
        add_check "$id" "$title" pass "$sev" "$mp mounted with nodev,nosuid,noexec"
    else
        add_check "$id" "$title" fail "$sev" "$mp missing mount options:$missing (current: $opts)"
    fi
}

check_filesystem() {
    local out="$WORK_DIR/find.out" rc cnt sample dirs=() d

    # FS-001 world-writable files in system directories
    for d in /etc /usr /bin /sbin /lib /lib64 /boot /opt; do
        # skip symlinked dirs (merged /usr) to avoid walking /usr several times
        if [ -d "$d" ] && [ ! -L "$d" ]; then
            dirs[${#dirs[@]}]="$d"
        fi
    done
    if [ "${#dirs[@]}" -gt 0 ]; then
        run_to "$FIND_TIMEOUT" find "${dirs[@]}" -xdev -type f -perm -0002 -print > "$out" 2>/dev/null
        rc=$?
        cnt="$(wc -l < "$out" 2>/dev/null | tr -d ' ')"
        cnt="$(uint_or "$cnt" 0)"
        sample="$(head -n 5 "$out" 2>/dev/null | tr '\n' ' ')"
        if [ "$rc" -eq 124 ]; then
            add_check FS-001 "No world-writable files in system directories" warn high "search timed out after ${FIND_TIMEOUT}s; $cnt found so far: $sample"
        elif [ "$cnt" -eq 0 ]; then
            add_check FS-001 "No world-writable files in system directories" pass high "none found in ${dirs[*]}"
        else
            add_check FS-001 "No world-writable files in system directories" fail high "$cnt world-writable file(s), e.g. $sample"
        fi
    else
        add_check FS-001 "No world-writable files in system directories" skip high "no system directories found"
    fi

    # FS-002 SUID/SGID audit
    run_to "$FIND_TIMEOUT" find / -xdev "${_FIND_PRUNE[@]}" -type f '(' -perm -4000 -o -perm -2000 ')' -print > "$out" 2>/dev/null
    rc=$?
    cnt="$(wc -l < "$out" 2>/dev/null | tr -d ' ')"
    cnt="$(uint_or "$cnt" 0)"
    local odd
    odd="$(grep -E '^/(tmp|var/tmp|home|dev/shm|root|srv|mnt|media)/' "$out" 2>/dev/null | head -n 5 | tr '\n' ' ')"
    # /home, /tmp ... may be separate filesystems, look there explicitly as well
    local extra
    extra="$(run_to 60 find /tmp /var/tmp /dev/shm /home -xdev -type f '(' -perm -4000 -o -perm -2000 ')' -print 2>/dev/null | head -n 5 | tr '\n' ' ')"
    odd="$odd$extra"
    if [ "$rc" -eq 124 ]; then
        add_check FS-002 "SUID/SGID binaries audit" warn medium "search timed out after ${FIND_TIMEOUT}s; $cnt SUID/SGID files counted so far"
    elif [ -n "${odd// /}" ]; then
        add_check FS-002 "SUID/SGID binaries audit" fail medium "$cnt SUID/SGID files on root fs; suspicious locations: $odd"
    else
        add_check FS-002 "SUID/SGID binaries audit" pass medium "$cnt SUID/SGID files on the root filesystem, none in temp/home directories"
    fi

    # FS-003 unowned files
    run_to "$FIND_TIMEOUT" find / -xdev "${_FIND_PRUNE[@]}" '(' -nouser -o -nogroup ')' -print > "$out" 2>/dev/null
    rc=$?
    cnt="$(wc -l < "$out" 2>/dev/null | tr -d ' ')"
    cnt="$(uint_or "$cnt" 0)"
    sample="$(head -n 5 "$out" 2>/dev/null | tr '\n' ' ')"
    if [ "$rc" -eq 124 ]; then
        add_check FS-003 "No unowned files or directories" warn medium "search timed out after ${FIND_TIMEOUT}s; $cnt found so far: $sample"
    elif [ "$cnt" -eq 0 ]; then
        add_check FS-003 "No unowned files or directories" pass medium "no files without a valid owner or group on the root filesystem"
    else
        add_check FS-003 "No unowned files or directories" fail medium "$cnt file(s) without valid user/group, e.g. $sample"
    fi

    # FS-004 /tmp mount options
    _check_mount_hardening FS-004 "/tmp mounted with nodev,nosuid,noexec" /tmp medium

    # FS-005 sticky bit on world-writable directories
    run_to "$FIND_TIMEOUT" find / -xdev "${_FIND_PRUNE[@]}" -type d -perm -0002 ! -perm -1000 -print > "$out" 2>/dev/null
    rc=$?
    cnt="$(wc -l < "$out" 2>/dev/null | tr -d ' ')"
    cnt="$(uint_or "$cnt" 0)"
    sample="$(head -n 5 "$out" 2>/dev/null | tr '\n' ' ')"
    if [ "$rc" -eq 124 ]; then
        add_check FS-005 "Sticky bit on world-writable directories" warn medium "search timed out after ${FIND_TIMEOUT}s; $cnt found so far"
    elif [ "$cnt" -eq 0 ]; then
        add_check FS-005 "Sticky bit on world-writable directories" pass medium "all world-writable directories have the sticky bit"
    else
        add_check FS-005 "Sticky bit on world-writable directories" fail medium "$cnt world-writable director(y/ies) without sticky bit, e.g. $sample"
    fi

    # FS-006 /dev/shm mount options
    _check_mount_hardening FS-006 "/dev/shm mounted with nodev,nosuid,noexec" /dev/shm low

    # FS-007 filesystem capacity
    if [ -s "$DISK_TSV" ]; then
        local crit warnl
        crit="$(awk -F'\t' '$2 >= 95 { printf "%s(%s%%) ", $1, $2 }' "$DISK_TSV")"
        warnl="$(awk -F'\t' '$2 >= 85 && $2 < 95 { printf "%s(%s%%) ", $1, $2 }' "$DISK_TSV")"
        if [ -n "$crit" ]; then
            add_check FS-007 "Filesystem capacity" fail medium "critically full: $crit${warnl:+; high: $warnl}"
        elif [ -n "$warnl" ]; then
            add_check FS-007 "Filesystem capacity" warn medium "above 85%: $warnl"
        else
            add_check FS-007 "Filesystem capacity" pass medium "all filesystems below 85% usage"
        fi
    else
        add_check FS-007 "Filesystem capacity" skip medium "disk usage not available"
    fi

    # FS-008 bootloader configuration permissions
    local g found=0 gbad=""
    for g in /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg /boot/grub2/user.cfg; do
        [ -f "$g" ] || continue
        found=1
        local gm
        gm="$(stat -c '%a' "$g" 2>/dev/null)"
        case "$g" in
            /boot/efi/*) continue ;;   # vfat has no unix permissions
        esac
        if ! perm_within "$gm" 600; then
            gbad="$gbad $g($gm)"
        fi
    done
    if [ "$found" -eq 0 ]; then
        add_check FS-008 "Bootloader configuration permissions" skip low "no grub.cfg found (container or non-GRUB boot)"
    elif [ -z "$gbad" ]; then
        add_check FS-008 "Bootloader configuration permissions" pass low "grub configuration readable by root only"
    else
        add_check FS-008 "Bootloader configuration permissions" warn low "grub configuration readable by non-root:$gbad"
    fi
}

# ----------------------------------------------------------------------------
# Compliance checks - network / kernel parameters
# ----------------------------------------------------------------------------
sysctl_value() {
    local key="$1" path
    path="/proc/sys/${key//.//}"
    [ -r "$path" ] || return 1
    tr -d '[:space:]' < "$path" 2>/dev/null
}

# check_sysctl ID TITLE KEY EXPECTED SEVERITY [eq|ge] [FAIL_STATUS]
check_sysctl() {
    local id="$1" title="$2" key="$3" exp="$4" sev="$5" op="${6:-eq}" failst="${7:-fail}" val ok=0
    if ! val="$(sysctl_value "$key")" || [ -z "$val" ]; then
        add_check "$id" "$title" skip "$sev" "$key not available on this kernel"
        return 0
    fi
    case "$op" in
        ge) if is_uint "$val" && [ "$val" -ge "$exp" ]; then ok=1; fi ;;
        *)  [ "$val" = "$exp" ] && ok=1 ;;
    esac
    if [ "$ok" -eq 1 ]; then
        add_check "$id" "$title" pass "$sev" "$key = $val"
    else
        add_check "$id" "$title" "$failst" "$sev" "$key = $val (expected $( [ "$op" = ge ] && echo '>= ' )$exp)"
    fi
}

host_routes_packets() {
    # container hosts / routers legitimately forward packets
    have docker && return 0
    have podman && return 0
    have kubelet && return 0
    have k3s && return 0
    have crio && return 0
    have containerd && return 0
    [ -d /etc/kubernetes ] && return 0
    [ -d /var/lib/libvirt ] && have virsh && return 0
    return 1
}

check_firewall() {
    local detail="" active=0
    if have ufw; then
        if run_to 20 ufw status 2>/dev/null | grep -qi '^Status: active'; then
            active=1; detail="ufw active"
        else
            detail="ufw installed but inactive"
        fi
    fi
    if [ "$active" -eq 0 ] && have firewall-cmd; then
        if svc_active firewalld || [ "$(run_to 20 firewall-cmd --state 2>/dev/null)" = "running" ]; then
            active=1
            local zone
            zone="$(run_to 20 firewall-cmd --get-default-zone 2>/dev/null)"
            detail="firewalld running${zone:+, default zone $zone}"
        else
            detail="${detail:+$detail; }firewalld installed but not running"
        fi
    fi
    if [ "$active" -eq 0 ] && have nft && is_root; then
        local nrules
        nrules="$(run_to 20 nft list ruleset 2>/dev/null | grep -cE '^[[:space:]]+(type .* hook|.*(accept|drop|reject))' )"
        if [ "$(uint_or "$nrules" 0)" -gt 2 ]; then
            active=1; detail="nftables ruleset loaded ($nrules rule lines)"
        fi
    fi
    if [ "$active" -eq 0 ] && have iptables && is_root; then
        local irules pol
        irules="$(run_to 20 iptables -S 2>/dev/null | grep -c '^-A')"
        pol="$(run_to 20 iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/ {print $3}')"
        if [ "$(uint_or "$irules" 0)" -gt 0 ] || [ "$pol" = "DROP" ]; then
            active=1; detail="iptables rules present ($irules rules, INPUT policy ${pol:-?})"
        fi
    fi
    if [ "$active" -eq 1 ]; then
        add_check NET-001 "Host firewall active" pass high "$detail"
    elif ! is_root; then
        add_check NET-001 "Host firewall active" skip high "cannot inspect firewall state without root"
    else
        add_check NET-001 "Host firewall active" fail high "${detail:-no ufw, firewalld, nftables or iptables rules active}"
    fi
}

check_network() {
    check_firewall

    # NET-002 ip forwarding (legitimate on container hosts / routers)
    local fwd
    if fwd="$(sysctl_value net.ipv4.ip_forward)" && [ -n "$fwd" ]; then
        if [ "$fwd" = "0" ]; then
            add_check NET-002 "IPv4 forwarding disabled" pass medium "net.ipv4.ip_forward = 0"
        elif host_routes_packets; then
            add_check NET-002 "IPv4 forwarding disabled" warn medium "net.ipv4.ip_forward = 1 (container runtime / virtualisation host detected - probably intentional)"
        else
            add_check NET-002 "IPv4 forwarding disabled" fail medium "net.ipv4.ip_forward = 1 and host does not look like a router or container host"
        fi
    else
        add_check NET-002 "IPv4 forwarding disabled" skip medium "net.ipv4.ip_forward not available"
    fi

    # NET-003 reverse path filtering (1 strict or 2 loose are both acceptable)
    local rp
    if rp="$(sysctl_value net.ipv4.conf.all.rp_filter)" && [ -n "$rp" ]; then
        local rpd
        rpd="$(sysctl_value net.ipv4.conf.default.rp_filter 2>/dev/null || true)"
        if [ "$rp" = "1" ] || [ "$rp" = "2" ] || [ "$rpd" = "1" ]; then
            add_check NET-003 "Reverse path filtering enabled" pass medium "net.ipv4.conf.all.rp_filter = $rp, default = ${rpd:-?}"
        else
            add_check NET-003 "Reverse path filtering enabled" fail medium "net.ipv4.conf.all.rp_filter = $rp, default = ${rpd:-?} (expected 1)"
        fi
    else
        add_check NET-003 "Reverse path filtering enabled" skip medium "rp_filter not available"
    fi

    check_sysctl NET-004 "TCP SYN cookies enabled" net.ipv4.tcp_syncookies 1 medium
    check_sysctl NET-005 "ICMP redirects not accepted" net.ipv4.conf.all.accept_redirects 0 medium
    check_sysctl NET-006 "Source routed packets not accepted" net.ipv4.conf.all.accept_source_route 0 medium
    check_sysctl NET-007 "ICMP redirects not sent" net.ipv4.conf.all.send_redirects 0 low eq warn
    check_sysctl NET-008 "Martian packets logged" net.ipv4.conf.all.log_martians 1 low eq warn
    check_sysctl NET-009 "Broadcast ICMP echo ignored" net.ipv4.icmp_echo_ignore_broadcasts 1 low
}

check_legacy_services() {
    # SVC-001 insecure legacy network services
    local bad="" u
    for u in telnet.socket telnetd xinetd rsh.socket rlogin.socket rexec.socket tftp.socket tftpd-hpa vsftpd proftpd ypserv rpcbind.socket; do
        if svc_active "$u"; then
            bad="$bad ${u}"
        fi
    done
    local p
    for p in 23/tcp 512/tcp 513/tcp 514/tcp 69/udp; do
        if port_listening "$p"; then
            bad="$bad port:$p"
        fi
    done
    if [ -z "$bad" ]; then
        add_check SVC-001 "No insecure legacy services" pass high "telnet/rsh/rlogin/tftp/ftp/NIS services are not active"
    else
        add_check SVC-001 "No insecure legacy services" fail high "active legacy services:$bad"
    fi
}

check_kernel_params() {
    # KRN-001 ASLR
    check_sysctl KRN-001 "Address space layout randomisation (ASLR)" kernel.randomize_va_space 2 high

    # KRN-002 core dumps
    local sd hardcore=0 storage=""
    sd="$(sysctl_value fs.suid_dumpable 2>/dev/null || true)"
    if grep -rhsE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d 2>/dev/null | grep -q .; then
        hardcore=1
    fi
    storage="$(grep -rhsE '^[[:space:]]*Storage[[:space:]]*=' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d 2>/dev/null | tail -n1 | awk -F= '{gsub(/[[:space:]]/, "", $2); print $2}')"
    if [ -z "$sd" ]; then
        add_check KRN-002 "Core dumps restricted" skip medium "fs.suid_dumpable not available"
    elif [ "$sd" != "0" ] && [ "$sd" != "2" ]; then
        add_check KRN-002 "Core dumps restricted" fail medium "fs.suid_dumpable = $sd (setuid programs may dump core)"
    elif [ "$hardcore" -eq 1 ] || [ "$storage" = "none" ]; then
        add_check KRN-002 "Core dumps restricted" pass medium "fs.suid_dumpable = $sd; core dumps disabled (limits hard core 0: $hardcore, coredump Storage: ${storage:-default})"
    else
        add_check KRN-002 "Core dumps restricted" warn medium "fs.suid_dumpable = $sd but no '* hard core 0' limit and systemd-coredump Storage=${storage:-default}"
    fi

    # KRN-003 running kernel is the newest installed kernel
    if is_container; then
        add_check KRN-003 "Running kernel is the newest installed" skip medium "container - kernel is provided by the host"
    elif [ -z "$NEWEST_INSTALLED_KERNEL" ]; then
        add_check KRN-003 "Running kernel is the newest installed" skip medium "could not determine installed kernel packages (running: $OS_KERNEL)"
    elif [ "$NEWEST_INSTALLED_KERNEL" = "$OS_KERNEL" ]; then
        add_check KRN-003 "Running kernel is the newest installed" pass medium "running $OS_KERNEL"
    else
        add_check KRN-003 "Running kernel is the newest installed" warn medium "running $OS_KERNEL but $NEWEST_INSTALLED_KERNEL is installed - reboot needed to activate it"
    fi

    check_sysctl KRN-004 "dmesg restricted to privileged users" kernel.dmesg_restrict 1 low eq warn
    check_sysctl KRN-005 "Kernel pointers hidden" kernel.kptr_restrict 1 low ge warn
    check_sysctl KRN-006 "ptrace scope restricted" kernel.yama.ptrace_scope 1 low ge warn
}

# ----------------------------------------------------------------------------
# Compliance checks - mandatory access control, audit, time, cron, logging
# ----------------------------------------------------------------------------
check_mac() {
    local mode=""
    if have getenforce; then
        mode="$(getenforce 2>/dev/null)"
    elif [ -r /sys/fs/selinux/enforce ]; then
        if [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "1" ]; then mode="Enforcing"; else mode="Permissive"; fi
    fi

    if [ -n "$mode" ] && [ "$mode" != "Disabled" ]; then
        local cfg=""
        [ -r /etc/selinux/config ] && cfg="$(awk -F= '/^SELINUX=/ {print $2; exit}' /etc/selinux/config 2>/dev/null)"
        if [ "$mode" = "Enforcing" ]; then
            if [ -n "$cfg" ] && [ "$cfg" != "enforcing" ]; then
                add_check MAC-001 "Mandatory access control enforcing (SELinux/AppArmor)" warn high "SELinux enforcing now but configured '$cfg' for next boot"
            else
                add_check MAC-001 "Mandatory access control enforcing (SELinux/AppArmor)" pass high "SELinux enforcing"
            fi
        else
            add_check MAC-001 "Mandatory access control enforcing (SELinux/AppArmor)" warn high "SELinux is $mode (config: ${cfg:-unknown})"
        fi
        return 0
    fi

    # AppArmor
    local aa_enabled=""
    [ -r /sys/module/apparmor/parameters/enabled ] && aa_enabled="$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)"
    if [ "$aa_enabled" = "Y" ]; then
        local enf="?" comp="?"
        if [ -r /sys/kernel/security/apparmor/profiles ]; then
            enf="$(grep -c '(enforce)' /sys/kernel/security/apparmor/profiles 2>/dev/null)"
            comp="$(grep -c '(complain)' /sys/kernel/security/apparmor/profiles 2>/dev/null)"
        fi
        if [ "$enf" = "0" ]; then
            add_check MAC-001 "Mandatory access control enforcing (SELinux/AppArmor)" warn high "AppArmor enabled but no profiles in enforce mode ($comp complain)"
        else
            add_check MAC-001 "Mandatory access control enforcing (SELinux/AppArmor)" pass high "AppArmor enabled: $enf profile(s) enforce, $comp complain"
        fi
        return 0
    fi

    if is_container; then
        add_check MAC-001 "Mandatory access control enforcing (SELinux/AppArmor)" skip high "container - MAC is enforced by the host"
    elif [ "$mode" = "Disabled" ]; then
        add_check MAC-001 "Mandatory access control enforcing (SELinux/AppArmor)" fail high "SELinux is disabled"
    else
        add_check MAC-001 "Mandatory access control enforcing (SELinux/AppArmor)" fail high "neither SELinux nor AppArmor is active"
    fi
}

check_auditd() {
    if svc_active auditd; then
        local rules="?"
        if have auditctl && is_root; then
            rules="$(run_to 20 auditctl -l 2>/dev/null | grep -vc '^No rules')"
        fi
        if [ "$rules" = "0" ]; then
            add_check AUD-001 "auditd running" warn medium "auditd is running but no audit rules are loaded"
        else
            add_check AUD-001 "auditd running" pass medium "auditd active, $rules rule(s) loaded"
        fi
    elif is_container; then
        add_check AUD-001 "auditd running" skip medium "container - auditing is a host responsibility"
    elif have auditctl || [ -x /sbin/auditd ] || [ -x /usr/sbin/auditd ]; then
        add_check AUD-001 "auditd running" fail medium "auditd is installed but not running"
    else
        add_check AUD-001 "auditd running" fail medium "auditd is not installed"
    fi
}

check_time_sync() {
    local unit synced=""
    unit="$(any_svc_active chronyd chrony ntpd ntp ntpsec systemd-timesyncd openntpd)" || unit=""
    if have timedatectl; then
        synced="$(run_to 15 timedatectl show -p NTPSynchronized --value 2>/dev/null)"
        if [ -z "$synced" ]; then
            if run_to 15 timedatectl status 2>/dev/null | grep -qiE '(NTP synchronized|System clock synchronized): yes'; then
                synced="yes"
            else
                synced="no"
            fi
        fi
    fi
    if [ -n "$unit" ]; then
        if [ "$synced" = "no" ]; then
            add_check TIME-001 "Time synchronisation active" warn medium "$unit is running but the clock is not reported as synchronised"
        else
            add_check TIME-001 "Time synchronisation active" pass medium "$unit active${synced:+, synchronised: $synced}"
        fi
    elif is_container; then
        add_check TIME-001 "Time synchronisation active" skip medium "container - clock is provided by the host"
    else
        add_check TIME-001 "Time synchronisation active" fail medium "no chrony/ntp/systemd-timesyncd service is running"
    fi
}

check_cron() {
    if [ ! -e /etc/crontab ] && [ ! -d /etc/cron.d ]; then
        add_check CRON-001 "Cron file and directory permissions" skip medium "cron is not installed"
        return 0
    fi
    local bad="" f mode owner
    if [ -e /etc/crontab ]; then
        mode="$(stat -c '%a' /etc/crontab 2>/dev/null)"
        owner="$(stat -c '%U' /etc/crontab 2>/dev/null)"
        if ! perm_within "$mode" 600 || [ "$owner" != "root" ]; then
            bad="$bad /etc/crontab($owner:$mode)"
        fi
    fi
    for f in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$f" ] || continue
        mode="$(stat -c '%a' "$f" 2>/dev/null)"
        owner="$(stat -c '%U' "$f" 2>/dev/null)"
        if ! perm_within "$mode" 700 || [ "$owner" != "root" ]; then
            bad="$bad $f($owner:$mode)"
        fi
    done
    # world-writable cron job files are a direct privilege escalation
    local ww
    ww="$(find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron -xdev -type f -perm -0002 -print 2>/dev/null | head -n 5 | tr '\n' ' ')"
    if [ -n "$ww" ]; then
        add_check CRON-001 "Cron file and directory permissions" fail high "world-writable cron files: $ww"
    elif [ -z "$bad" ]; then
        add_check CRON-001 "Cron file and directory permissions" pass medium "/etc/crontab is 600 and cron directories are 700, owned by root"
    else
        add_check CRON-001 "Cron file and directory permissions" fail medium "accessible by group/other:$bad"
    fi

    # CRON-002 cron access restricted
    if [ -e /etc/cron.allow ]; then
        add_check CRON-002 "Cron access restricted to authorised users" pass low "/etc/cron.allow present"
    elif [ -e /etc/cron.deny ]; then
        add_check CRON-002 "Cron access restricted to authorised users" warn low "only /etc/cron.deny present; an allow-list (/etc/cron.allow) is preferred"
    else
        add_check CRON-002 "Cron access restricted to authorised users" warn low "neither /etc/cron.allow nor /etc/cron.deny exists"
    fi
}

check_logging() {
    local unit
    unit="$(any_svc_active rsyslog syslog-ng)" || unit=""
    local persistent=0 storage=""
    [ -d /var/log/journal ] && persistent=1
    storage="$(grep -rhsE '^[[:space:]]*Storage[[:space:]]*=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d 2>/dev/null | tail -n1 | awk -F= '{gsub(/[[:space:]]/, "", $2); print $2}')"
    [ "$storage" = "persistent" ] && persistent=1
    [ "$storage" = "volatile" ] && persistent=0
    [ "$storage" = "none" ] && persistent=0
    if [ -n "$unit" ]; then
        add_check LOG-001 "Persistent system logging" pass medium "$unit active (journald persistent: $persistent)"
    elif [ "$persistent" -eq 1 ]; then
        add_check LOG-001 "Persistent system logging" pass medium "systemd-journald with persistent storage"
    elif is_container; then
        add_check LOG-001 "Persistent system logging" skip medium "container - logging handled by the runtime"
    else
        add_check LOG-001 "Persistent system logging" fail medium "no syslog daemon running and journald storage is not persistent"
    fi
}

# Runs every distro independent check. The distro script must have collected
# system information (for port / disk based checks) and set
# NEWEST_INSTALLED_KERNEL before calling this.
run_common_compliance() {
    log "running common compliance checks"
    check_ssh
    check_accounts
    check_filesystem
    check_network
    check_legacy_services
    check_kernel_params
    check_mac
    check_auditd
    check_time_sync
    check_cron
    check_logging
}

# =============================================================================
# Enterprise Linux family helpers (CentOS / Rocky / AlmaLinux / Oracle / RHEL)
# =============================================================================
EL_PM=""              # dnf | yum
EL_SECMETA="unknown"  # yes | no | unknown - do the repos ship updateinfo metadata?

el_detect_pm() {
    if have dnf; then
        EL_PM="dnf"
    elif have yum; then
        EL_PM="yum"
    else
        EL_PM=""
        add_error "neither dnf nor yum found; package information unavailable"
        return 1
    fi
    return 0
}

el_installed_count() {
    if have rpm; then
        local n
        n="$(run_to 120 rpm -qa 2>/dev/null | wc -l | tr -d ' ')"
        PKG_INSTALLED_COUNT="$(uint_or "$n" 0)"
        if [ "$PKG_INSTALLED_COUNT" -eq 0 ]; then
            add_error "rpm -qa returned no packages (rpm database locked or corrupt?)"
        fi
    else
        add_error "rpm command not found"
    fi
}

el_refresh_cache() {
    [ -n "$EL_PM" ] || return 0
    [ "$REFRESH_CACHE" -eq 1 ] || { log "metadata refresh skipped (--no-refresh)"; return 0; }
    is_root || { add_error "not root: skipping $EL_PM makecache"; return 0; }
    log "refreshing $EL_PM metadata"
    local rc errf="$WORK_DIR/makecache.err"
    if [ "$EL_PM" = "yum" ]; then
        run_to "$PM_TIMEOUT" yum -q makecache fast > /dev/null 2> "$errf"
        rc=$?
        if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
            # "fast" does not exist on every yum build
            run_to "$PM_TIMEOUT" yum -q makecache > /dev/null 2> "$errf"
            rc=$?
        fi
    else
        run_to "$PM_TIMEOUT" dnf -q makecache > /dev/null 2> "$errf"
        rc=$?
    fi
    if [ "$rc" -eq 124 ]; then
        add_error "$EL_PM makecache timed out after ${PM_TIMEOUT}s; results may be based on stale metadata"
    elif [ "$rc" -ne 0 ]; then
        add_error "$EL_PM makecache failed (rc=$rc): $(first_line "$errf"); results may be based on stale metadata"
    fi
    return 0
}

# Parse "check-update" output (stdin) into: name.arch \t version \t repo
# Handles yum's habit of wrapping long package names over several lines and
# stops at the "Obsoleting Packages" section.
el_parse_check_update() {
    awk -v OFS='\t' '
        function flush() { n = 0; buf[1] = ""; buf[2] = ""; buf[3] = "" }
        BEGIN { n = 0 }
        /^Obsoleting Packages/ { exit }
        /^Security:/ { next }
        /^Last metadata expiration/ { next }
        /^Loaded plugins/ { next }
        /^Loading mirror speeds/ { next }
        /^[[:space:]]*\*/ { next }
        /^[[:space:]]*$/ { flush(); next }
        {
            for (i = 1; i <= NF; i++) {
                if (n == 0 && $i !~ /\.(x86_64|i[3-6]86|noarch|aarch64|ppc64le|ppc64|s390x|armv7hl|src)$/) {
                    # not the start of a package record - ignore the whole line
                    break
                }
                n++
                buf[n] = $i
                if (n == 3) {
                    print buf[1], buf[2], buf[3]
                    flush()
                }
            }
        }'
}

# Parse "updateinfo list" output (stdin) into: name.arch \t advisory \t severity
# Only security advisories are kept; when several advisories touch the same
# package the most severe one wins.
el_parse_updateinfo() {
    awk -v OFS='\t' '
        function rank(s) { return s == "critical" ? 4 : s == "important" ? 3 : s == "moderate" ? 2 : s == "low" ? 1 : 0 }
        function nevra_key(n,   arch, cnt, parts, i, name) {
            arch = ""
            if (match(n, /\.[^.]+$/)) { arch = substr(n, RSTART + 1); n = substr(n, 1, RSTART - 1) }
            cnt = split(n, parts, "-")
            if (cnt < 3) return ""
            name = parts[1]
            for (i = 2; i <= cnt - 2; i++) name = name "-" parts[i]
            return name "." arch
        }
        NF >= 3 && $1 ~ /^[A-Za-z]+-[0-9]/ {
            type = $2
            if (type !~ /[Ss]ec/) next
            sev = "unknown"
            if (index(type, "/") > 0) { split(type, t, "/"); sev = tolower(t[1]) }
            if (sev !~ /^(critical|important|moderate|low)$/) sev = "unknown"
            key = nevra_key($NF)
            if (key == "") next
            if (!(key in adv) || rank(sev) >= rank(best[key])) { adv[key] = $1; best[key] = sev }
        }
        END { for (k in adv) print k, adv[k], best[k] }'
}

# Does at least one enabled repository ship updateinfo (errata) metadata?
el_has_security_metadata() {
    [ "$EL_SECMETA" = "yes" ] && return 0
    [ "$EL_SECMETA" = "no" ] && return 1
    local out
    if [ "$EL_PM" = "dnf" ]; then
        out="$(run_to "$PM_TIMEOUT" dnf -q updateinfo list --all 2>/dev/null | awk '$1 ~ /^[A-Za-z]+-[0-9]/ { print; n++ } n >= 3 { exit }')"
    else
        out="$(run_to "$PM_TIMEOUT" yum -q updateinfo list all 2>/dev/null | awk '$1 ~ /^[A-Za-z]+-[0-9]/ { print; n++ } n >= 3 { exit }')"
    fi
    if [ -n "$out" ]; then
        EL_SECMETA="yes"
        return 0
    fi
    EL_SECMETA="no"
    return 1
}

el_collect_updates() {
    [ -n "$EL_PM" ] || return 0
    log "collecting pending updates via $EL_PM check-update"
    local cu="$WORK_DIR/check_update.out" cue="$WORK_DIR/check_update.err" rc
    run_to "$PM_TIMEOUT" "$EL_PM" -q check-update > "$cu" 2> "$cue"
    rc=$?
    case "$rc" in
        0)   log "no updates available"; return 0 ;;
        100) ;;
        124) add_error "$EL_PM check-update timed out after ${PM_TIMEOUT}s; pending updates unknown"; return 0 ;;
        *)   add_error "$EL_PM check-update failed (rc=$rc): $(first_line "$cue"); pending updates unknown"; return 0 ;;
    esac

    local upd="$WORK_DIR/updates.tsv" inst="$WORK_DIR/installed.tsv" advf="$WORK_DIR/advisories.tsv"
    el_parse_check_update < "$cu" > "$upd" 2>/dev/null
    if [ ! -s "$upd" ]; then
        add_error "$EL_PM check-update reported updates (rc=100) but its output could not be parsed"
        return 0
    fi

    run_to 120 rpm -qa --qf '%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort -t "$_TAB" -k1,1 -k2,2V > "$inst" 2>/dev/null
    : > "$advf"

    # Security classification through updateinfo metadata
    local ui="$WORK_DIR/updateinfo.out" uie="$WORK_DIR/updateinfo.err" urc
    if [ "$EL_PM" = "dnf" ]; then
        run_to "$PM_TIMEOUT" dnf -q updateinfo list --security > "$ui" 2> "$uie"
        urc=$?
        if [ "$urc" -ne 0 ] || [ ! -s "$ui" ]; then
            run_to "$PM_TIMEOUT" dnf -q updateinfo list security > "$ui" 2> "$uie"
            urc=$?
        fi
    else
        run_to "$PM_TIMEOUT" yum -q updateinfo list security > "$ui" 2> "$uie"
        urc=$?
    fi
    if [ "$urc" -eq 124 ]; then
        add_error "$EL_PM updateinfo timed out; security classification unavailable"
    elif [ "$urc" -ne 0 ]; then
        add_error "$EL_PM updateinfo failed (rc=$urc): $(first_line "$uie"); security classification unavailable"
    fi
    el_parse_updateinfo < "$ui" > "$advf" 2>/dev/null

    if [ ! -s "$advf" ]; then
        if el_has_security_metadata; then
            log "updateinfo metadata present; none of the pending updates is a security advisory"
        else
            add_error "enabled repositories provide no updateinfo (errata) metadata; pending updates cannot be classified as security/non-security and are reported with security=false, severity=unknown"
        fi
    else
        EL_SECMETA="yes"
    fi

    awk -F'\t' -v OFS='\t' -v instf="$inst" -v advf="$advf" '
        BEGIN {
            while ((getline line < instf) > 0) { split(line, a, "\t"); inst[a[1]] = a[2] }
            close(instf)
            while ((getline line < advf) > 0) { split(line, a, "\t"); adv[a[1]] = a[2]; sev[a[1]] = a[3] }
            close(advf)
        }
        NF >= 2 {
            key = $1; name = key; sub(/\.[^.]+$/, "", name)
            cur = (key in inst) ? inst[key] : ""
            sub(/^0:/, "", cur)
            cand = $2; sub(/^0:/, "", cand)
            if (key in adv) print name, cur, cand, "true", adv[key], sev[key]
            else            print name, cur, cand, "false", "", "unknown"
        }' "$upd" >> "$PENDING_TSV" 2>/dev/null
    return 0
}

# Newest installed kernel of the same flavour as the running one (sets
# NEWEST_INSTALLED_KERNEL in "uname -r" format).
el_newest_kernel() {
    have rpm || return 0
    local running="$OS_KERNEL" pkgs list
    case "$running" in
        *uek*) pkgs="kernel-uek kernel-uek-core" ;;
        *rt*)  pkgs="kernel-rt kernel-rt-core" ;;
        *)     pkgs="kernel kernel-core kernel-lt kernel-ml" ;;
    esac
    # shellcheck disable=SC2086
    list="$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' $pkgs 2>/dev/null | grep -v 'is not installed' | sort -V | tail -n1)"
    if [ -n "$list" ]; then
        NEWEST_INSTALLED_KERNEL="$list"
    fi
}

el_reboot_required() {
    local rc out
    if is_container; then
        REBOOT_REQUIRED="false"
        return 0
    fi
    if have needs-restarting; then
        out="$(run_to 120 needs-restarting -r 2>&1)"
        rc=$?
        case "$rc" in
            0) REBOOT_REQUIRED="false"; return 0 ;;
            1) REBOOT_REQUIRED="true"; return 0 ;;
            *) add_error "needs-restarting -r failed (rc=$rc): $(flatten "${out:0:200}"); falling back to kernel comparison" ;;
        esac
    elif [ "$EL_PM" = "dnf" ] && run_to 60 dnf -q needs-restarting --help > /dev/null 2>&1; then
        out="$(run_to 120 dnf -q needs-restarting -r 2>&1)"
        rc=$?
        case "$rc" in
            0) REBOOT_REQUIRED="false"; return 0 ;;
            1) REBOOT_REQUIRED="true"; return 0 ;;
            *) add_error "dnf needs-restarting -r failed (rc=$rc); falling back to kernel comparison" ;;
        esac
    else
        add_error "needs-restarting not available (install yum-utils / dnf-utils); reboot requirement derived from kernel version only"
    fi
    if [ -n "$NEWEST_INSTALLED_KERNEL" ] && [ "$NEWEST_INSTALLED_KERNEL" != "$OS_KERNEL" ]; then
        REBOOT_REQUIRED="true"
    else
        REBOOT_REQUIRED="false"
    fi
}

# UPD-001 automatic updates (dnf-automatic / yum-cron)
el_check_auto_updates() {
    local detail="" status="fail"
    if svc_enabled dnf-automatic.timer || svc_active dnf-automatic.timer; then
        local apply=""
        [ -r /etc/dnf/automatic.conf ] && apply="$(awk -F= '/^[[:space:]]*apply_updates/ { gsub(/[[:space:]]/, "", $2); print tolower($2); exit }' /etc/dnf/automatic.conf 2>/dev/null)"
        if [ "$apply" = "yes" ] || [ "$apply" = "true" ] || [ "$apply" = "1" ]; then
            status="pass"; detail="dnf-automatic.timer enabled, apply_updates=$apply"
        else
            status="warn"; detail="dnf-automatic.timer enabled but apply_updates=${apply:-no} (download/notify only)"
        fi
    elif svc_enabled dnf-automatic-install.timer || svc_active dnf-automatic-install.timer; then
        status="pass"; detail="dnf-automatic-install.timer enabled"
    elif svc_enabled dnf-automatic-notifyonly.timer || svc_enabled dnf-automatic-download.timer; then
        status="warn"; detail="dnf-automatic notify/download timer enabled; updates are not applied automatically"
    elif svc_enabled yum-cron || svc_active yum-cron; then
        local apply=""
        [ -r /etc/yum/yum-cron.conf ] && apply="$(awk -F= '/^[[:space:]]*apply_updates/ { gsub(/[[:space:]]/, "", $2); print tolower($2); exit }' /etc/yum/yum-cron.conf 2>/dev/null)"
        if [ "$apply" = "yes" ]; then
            status="pass"; detail="yum-cron enabled, apply_updates=yes"
        else
            status="warn"; detail="yum-cron enabled but apply_updates=${apply:-no}"
        fi
    elif [ -e /etc/cron.daily/0yum-daily.cron ] || [ -e /etc/cron.daily/yum-autoupdate ]; then
        status="warn"; detail="legacy yum daily cron present"
    else
        detail="neither dnf-automatic nor yum-cron is enabled"
    fi
    add_check UPD-001 "Automatic updates configured" "$status" medium "$detail"
}

# EL-001 repository GPG signature checking
el_check_gpgcheck() {
    local bad="" f
    for f in /etc/yum.conf /etc/dnf/dnf.conf; do
        [ -r "$f" ] || continue
        if grep -qsE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*(0|no|false)' "$f" 2>/dev/null; then
            bad="$bad $f"
        fi
    done
    if [ -d /etc/yum.repos.d ]; then
        # only repos that are enabled matter
        local hits
        hits="$(awk '
            function flush() { if (name != "" && enabled && nogpg) printf "%s ", name }
            /^\[/ { flush(); name = $0; gsub(/[][]/, "", name); enabled = 1; nogpg = 0; next }
            /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(0|no|false)/ { enabled = 0 }
            /^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*(0|no|false)/ { nogpg = 1 }
            END { flush() }' /etc/yum.repos.d/*.repo 2>/dev/null)"
        [ -n "$hits" ] && bad="$bad repos: $hits"
    fi
    if [ -z "$bad" ]; then
        add_check EL-001 "Package signature checking (gpgcheck) enabled" pass high "gpgcheck is enabled globally and for all enabled repositories"
    else
        add_check EL-001 "Package signature checking (gpgcheck) enabled" fail high "gpgcheck disabled in:$bad"
    fi
}

# EL-002 system wide crypto policy (EL8+)
el_check_crypto_policy() {
    if ! have update-crypto-policies; then
        add_check EL-002 "System-wide crypto policy" skip medium "crypto-policies not available on this release"
        return 0
    fi
    local pol
    pol="$(run_to 20 update-crypto-policies --show 2>/dev/null)"
    case "$pol" in
        DEFAULT*|FUTURE*|FIPS*) add_check EL-002 "System-wide crypto policy" pass medium "crypto policy $pol" ;;
        LEGACY*) add_check EL-002 "System-wide crypto policy" fail medium "crypto policy LEGACY enables weak algorithms" ;;
        "") add_check EL-002 "System-wide crypto policy" skip medium "could not determine crypto policy" ;;
        *) add_check EL-002 "System-wide crypto policy" warn medium "custom crypto policy $pol" ;;
    esac
}

# Number of enabled repositories (0 when it cannot be determined)
el_enabled_repo_count() {
    [ -n "$EL_PM" ] || { printf '0'; return 0; }
    local n
    n="$(run_to "$PM_TIMEOUT" "$EL_PM" -q repolist enabled 2>/dev/null | awk 'NR > 1 && NF > 0 && $1 !~ /^(repolist:|Loaded|Loading|\*)/ { n++ } END { print n + 0 }')"
    uint_or "$n" 0
}
