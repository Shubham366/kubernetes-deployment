#!/usr/bin/env bash
# =============================================================================
# patch_common.sh - shared library for the patch / rollback / check scripts
#
# Sourced by patch_ubuntu.sh, patch_centos.sh, patch_rhel.sh,
# pre_patch_check.sh and post_patch_check.sh. Provides:
#   * argument parsing for the patch scripts
#       --patch-id ID --mode MODE [--packages "a b"] [--exclude "x y"]
#       [--no-kernel] [--dry-run] [--rollback] --output FILE
#   * JSON helpers (pure bash + awk, no jq / python on the target)
#   * per patch state directory  /var/lib/provisioner/patch/<patch_id>/
#       packages.before   name<TAB>version snapshot taken before patching
#       packages.after    snapshot after patching
#       transaction_id    yum/dnf history transaction id (EL only)
#       services.before   running services before patching (pre-check)
#       failed.before     failed units before patching (pre-check)
#       kernel.before     running kernel before patching (pre-check)
#       patch.log         full package manager output
#   * package snapshot / diff helpers
#   * patch + rollback report writers (always valid JSON)
#   * the yum/dnf patch and rollback engine shared by CentOS-like and RHEL
#
# Can also be executed directly:
#   patch_common.sh --snapshot FILE [--if-missing]   write a package snapshot
#   patch_common.sh --diff BEFORE AFTER              print name<TAB>from<TAB>to
#
# Compatibility: bash 4.2 (CentOS 7). "set -e" is intentionally NOT used.
# =============================================================================

set -uo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export LC_ALL=C
export LANG=C

# ----------------------------------------------------------------------------
# Global state
# ----------------------------------------------------------------------------
PATCH_SCHEMA_VERSION=1
PROV_BASE="${PROV_BASE:-/var/lib/provisioner}"

PATCH_ID=""
MODE=""
PACKAGES=""        # space separated
EXCLUDES=""        # space separated
NO_KERNEL=0
DRY_RUN=0
ROLLBACK=0
OUTPUT_FILE=""

STATE_DIR=""
LOG_FILE="/dev/null"
WORK_DIR=""
LOCK_DIR=""
LOCK_HELD=0

STATUS="failed"
STARTED_AT=""
FINISHED_AT=""
REBOOT_REQUIRED="false"
TRANSACTION_ID=""
ERRORS=()
REPORT_WRITTEN=0
UPDATED_TSV=""     # name \t from \t to
REVERTED_TSV=""    # name \t from \t to   (rollback)

OS_ID="unknown"
OS_VERSION=""
OS_VERSION_MAJOR=""
OS_PRETTY=""
HOST_NAME=""
PKG_FAMILY=""      # deb | rpm

PM_TIMEOUT="${PATCH_PM_TIMEOUT:-600}"          # metadata / query operations
TXN_TIMEOUT="${PATCH_TXN_TIMEOUT:-7200}"       # the actual update transaction

_TAB=$'\t'
_NL=$'\n'
_CR=$'\r'

# ----------------------------------------------------------------------------
# Basic helpers
# ----------------------------------------------------------------------------
now_iso() {
    date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
}

log() {
    local line
    line="$(printf '[%s] %s' "$(date -u +%H:%M:%S 2>/dev/null)" "$*")"
    printf '%s\n' "$line" >&2
    if [ "$LOG_FILE" != "/dev/null" ]; then
        printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

have() {
    command -v "$1" >/dev/null 2>&1
}

run_to() {
    local t="$1"
    shift
    if have timeout; then
        timeout "$t" "$@"
    else
        "$@"
    fi
}

flatten() {
    local s="${1-}"
    s=${s//$_NL/ }
    s=${s//$_CR/ }
    s=${s//$_TAB/ }
    printf '%s' "$s"
}

_push_error() {
    local m
    m="$(flatten "$*")"
    if [ "${#m}" -gt 700 ]; then
        m="${m:0:700}..."
    fi
    ERRORS[${#ERRORS[@]}]="$m"
}

# Fatal / real problems
add_error() {
    _push_error "$*"
    log "ERROR: $*"
}

# Non fatal findings - recorded in "errors" with a prefix so that the backend
# can tell them apart from hard failures.
add_warn() {
    _push_error "WARN: $*"
    log "WARN: $*"
}

add_note() {
    _push_error "NOTE: $*"
    log "NOTE: $*"
}

is_uint() {
    [[ "${1-}" =~ ^[0-9]+$ ]]
}

uint_or() {
    if is_uint "${1-}"; then printf '%s' "$1"; else printf '%s' "${2:-0}"; fi
}

is_root() {
    [ "$(id -u 2>/dev/null)" = "0" ]
}

first_line() {
    local f="$1"
    [ -r "$f" ] || return 0
    awk 'NF { print; exit }' "$f" 2>/dev/null
}

# run_logged TIMEOUT cmd [args...] - run with all output appended to LOG_FILE
run_logged() {
    local t="$1" rc
    shift
    printf '\n=== [%s] %s\n' "$(now_iso)" "$*" >> "$LOG_FILE" 2>/dev/null || true
    run_to "$t" "$@" >> "$LOG_FILE" 2>&1 < /dev/null
    rc=$?
    printf '=== rc=%s\n' "$rc" >> "$LOG_FILE" 2>/dev/null || true
    return "$rc"
}

# Last error-looking lines from the log (for the report)
log_error_tail() {
    [ -r "$LOG_FILE" ] || return 0
    tail -n 200 "$LOG_FILE" 2>/dev/null \
        | grep -E '^(E:|Err:|Error|error:|ERROR|Errors? |dpkg: error|Failed|Transaction check error|  file .* conflicts|Problem|No match for|Could not|Cannot )' \
        | tail -n 4 | tr '\n' ' ' | cut -c1-500
}

svc_active() {
    have systemctl || return 1
    systemctl is-active --quiet "$1" 2>/dev/null
}

is_container() {
    if have systemd-detect-virt && systemd-detect-virt --container --quiet 2>/dev/null; then
        return 0
    fi
    [ -f /.dockerenv ] && return 0
    [ -f /run/.containerenv ] && return 0
    return 1
}

# ----------------------------------------------------------------------------
# JSON helpers
# ----------------------------------------------------------------------------
# shellcheck disable=SC2016
_AWK_JESC='function jesc(s,   i,c,o,n){o="";n=length(s);for(i=1;i<=n;i++){c=substr(s,i,1);if(c=="\\")o=o "\\\\";else if(c=="\"")o=o "\\\"";else if(c=="\t")o=o "\\t";else if(c<" ")o=o " ";else o=o c}return o}'

json_escape() {
    printf '%s' "${1-}" | awk "$_AWK_JESC"' BEGIN{ORS=""} NR>1{print "\\n"} {print jesc($0)}'
}

json_str() {
    printf '"%s"' "$(json_escape "${1-}")"
}

json_bool() {
    case "${1-}" in
        true|TRUE|True|1|yes|YES) printf 'true' ;;
        *) printf 'false' ;;
    esac
}

json_lines_to_array() {
    awk "$_AWK_JESC"' BEGIN{printf "["} length($0)>0 { if(n++) printf ","; printf "\"%s\"", jesc($0) } END{printf "]"}'
}

_emit_errors_json() {
    if [ "${#ERRORS[@]}" -eq 0 ]; then
        printf '[]'
    else
        printf '%s\n' "${ERRORS[@]}" | json_lines_to_array
    fi
}

# name \t from \t to  ->  [{"name":..,"from":..,"to":..}]
_emit_pkg_changes_json() {
    local f="$1"
    if [ -n "$f" ] && [ -s "$f" ]; then
        awk -F'\t' "$_AWK_JESC"'
            BEGIN { printf "[" }
            length($1) > 0 {
                if (n++) printf ","
                printf "{\"name\":\"%s\",\"from\":\"%s\",\"to\":\"%s\"}", jesc($1), jesc($2), jesc($3)
            }
            END { printf "]" }' "$f"
    else
        printf '[]'
    fi
}

_utf8_clean() {
    # strip invalid UTF-8 sequences in place (best effort)
    local f="$1"
    if have iconv; then
        if iconv -f UTF-8 -t UTF-8 -c "$f" > "${f}.u8" 2>/dev/null && [ -s "${f}.u8" ]; then
            mv -f "${f}.u8" "$f" 2>/dev/null || true
        else
            rm -f "${f}.u8" 2>/dev/null
        fi
    fi
}

# ----------------------------------------------------------------------------
# OS detection
# ----------------------------------------------------------------------------
os_release_get() {
    local key="$1" file="${2:-/etc/os-release}"
    [ -r "$file" ] || return 0
    awk -F= -v k="$key" '$1 == k { v = $0; sub(/^[^=]*=/, "", v); gsub(/^[\042\047]|[\042\047]$/, "", v); print v; exit }' "$file" 2>/dev/null
}

detect_os() {
    if [ -r /etc/os-release ]; then
        OS_ID="$(os_release_get ID)"
        OS_VERSION="$(os_release_get VERSION_ID)"
        OS_PRETTY="$(os_release_get PRETTY_NAME)"
    elif [ -r /etc/centos-release ]; then
        OS_ID="centos"; OS_PRETTY="$(head -n1 /etc/centos-release)"
    elif [ -r /etc/redhat-release ]; then
        OS_ID="rhel"; OS_PRETTY="$(head -n1 /etc/redhat-release)"
    elif [ -r /etc/debian_version ]; then
        OS_ID="debian"; OS_VERSION="$(head -n1 /etc/debian_version)"
    fi
    if [ -z "$OS_VERSION" ] && [ -n "$OS_PRETTY" ]; then
        OS_VERSION="$(printf '%s' "$OS_PRETTY" | sed -n 's/[^0-9]*\([0-9][0-9.]*\).*/\1/p' | head -n1)"
    fi
    if [ -r /etc/centos-release ] && [[ "$OS_VERSION" =~ ^[0-9]+$ ]]; then
        local full
        full="$(sed -n 's/[^0-9]*\([0-9][0-9]*\.[0-9][0-9.]*\).*/\1/p' /etc/centos-release 2>/dev/null | head -n1)"
        [ -n "$full" ] && OS_VERSION="$full"
    fi
    [ -n "$OS_ID" ] || OS_ID="unknown"
    OS_ID="$(printf '%s' "$OS_ID" | tr '[:upper:]' '[:lower:]')"
    OS_VERSION_MAJOR="${OS_VERSION%%.*}"
    [ -n "$OS_PRETTY" ] || OS_PRETTY="$OS_ID $OS_VERSION"
    HOST_NAME="$(hostname -f 2>/dev/null)"
    if [ -z "$HOST_NAME" ] || [ "$HOST_NAME" = "localhost" ]; then
        HOST_NAME="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)"
    fi
    if have dpkg-query && have apt-get; then
        PKG_FAMILY="deb"
    elif have rpm; then
        PKG_FAMILY="rpm"
    else
        PKG_FAMILY=""
    fi
}

# ----------------------------------------------------------------------------
# Package snapshot / diff
# ----------------------------------------------------------------------------
# snapshot_packages FILE - "name<TAB>version" per installed package, sorted.
#   deb: name is ${binary:Package} (arch qualified for multi-arch packages)
#   rpm: name is NAME.ARCH, version is EPOCH:VERSION-RELEASE
snapshot_packages() {
    local file="$1" tmp="${1}.tmp.$$" rc=1
    mkdir -p "$(dirname "$file")" 2>/dev/null || true
    if have dpkg-query && have apt-get; then
        run_to 180 dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' 2>/dev/null \
            | awk -F'\t' 'substr($1, 2, 1) == "i" && length($3) > 0 { print $2 "\t" $3 }' \
            | sort -t "$_TAB" -k1,1 -k2,2V > "$tmp" 2>/dev/null
        rc=$?
    elif have rpm; then
        run_to 180 rpm -qa --qf '%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' 2>/dev/null \
            | grep -v '^gpg-pubkey\.' \
            | sort -t "$_TAB" -k1,1 -k2,2V > "$tmp" 2>/dev/null
        rc=$?
    else
        rm -f "$tmp" 2>/dev/null
        return 2
    fi
    if [ ! -s "$tmp" ]; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    mv -f "$tmp" "$file" 2>/dev/null || return 1
    chmod 0600 "$file" 2>/dev/null || true
    return 0
}

# diff_packages BEFORE AFTER - prints "name<TAB>from<TAB>to" for every package
# version present in AFTER but not in BEFORE. "from" is the (highest) version of
# the same package in BEFORE or empty for newly installed packages. Works for
# install-only packages (several kernel versions installed side by side).
diff_packages() {
    local before="$1" after="$2"
    [ -r "$after" ] || return 1
    [ -r "$before" ] || before=/dev/null
    awk -F'\t' -v OFS='\t' -v beforef="$before" '
        function plain(n) {
            sub(/\.(x86_64|i[3-6]86|noarch|aarch64|ppc64le|ppc64|s390x|armv7hl)$/, "", n)
            sub(/:[a-z0-9]+$/, "", n)
            return n
        }
        function strip0(v) { sub(/^0:/, "", v); return v }
        BEGIN {
            while ((getline line < beforef) > 0) {
                split(line, a, "\t")
                seen[a[1] SUBSEP a[2]] = 1
                last[a[1]] = a[2]
            }
            close(beforef)
        }
        NF >= 2 {
            if (!(($1 SUBSEP $2) in seen)) {
                from = ($1 in last) ? last[$1] : ""
                print plain($1), strip0(from), strip0($2)
            }
        }' "$after"
}

# packages_missing BEFORE NOW - prints "name<TAB>wanted<TAB>current" for every
# (name, version) of BEFORE that is not installed in NOW (rollback bookkeeping).
packages_missing() {
    local before="$1" nowf="$2"
    [ -r "$before" ] || return 1
    [ -r "$nowf" ] || return 1
    awk -F'\t' -v OFS='\t' -v nowf="$nowf" '
        BEGIN {
            while ((getline line < nowf) > 0) {
                split(line, a, "\t")
                seen[a[1] SUBSEP a[2]] = 1
                cur[a[1]] = a[2]
            }
            close(nowf)
        }
        NF >= 2 {
            if (!(($1 SUBSEP $2) in seen)) print $1, $2, (($1 in cur) ? cur[$1] : "")
        }' "$before"
}

# ----------------------------------------------------------------------------
# Argument parsing / state directory / locking
# ----------------------------------------------------------------------------
patch_usage() {
    cat >&2 <<'EOF'
Usage: patch_<distro>.sh --patch-id ID --mode MODE [--packages "a b"] [--exclude "x y"]
                         [--no-kernel] [--dry-run] --output FILE
       patch_<distro>.sh --rollback --patch-id ID --output FILE
  --patch-id ID      identifier; state is kept in /var/lib/provisioner/patch/<ID>/
  --mode MODE        security | all | packages
  --packages "a b"   packages (or advisory ids on EL) for --mode packages
  --exclude "x y"    packages / globs that must not be updated
  --no-kernel        do not update kernel packages
  --dry-run          only report what would be updated
  --rollback         revert the changes recorded for --patch-id
  --output FILE      where the JSON report is written
EOF
}

_split_list() {
    # normalise "a,b  c" -> "a b c"
    printf '%s' "${1-}" | tr ',\n\t' '   ' | tr -s ' ' | sed -e 's/^ //' -e 's/ $//'
}

patch_parse_args() {
    local unknown=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --patch-id)    PATCH_ID="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --patch-id=*)  PATCH_ID="${1#*=}"; shift ;;
            --mode)        MODE="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --mode=*)      MODE="${1#*=}"; shift ;;
            --packages)    PACKAGES="$(_split_list "${2-}")"; shift; [ $# -gt 0 ] && shift ;;
            --packages=*)  PACKAGES="$(_split_list "${1#*=}")"; shift ;;
            --exclude)     EXCLUDES="$(_split_list "${2-}")"; shift; [ $# -gt 0 ] && shift ;;
            --exclude=*)   EXCLUDES="$(_split_list "${1#*=}")"; shift ;;
            --output)      OUTPUT_FILE="${2-}"; shift; [ $# -gt 0 ] && shift ;;
            --output=*)    OUTPUT_FILE="${1#*=}"; shift ;;
            --no-kernel)   NO_KERNEL=1; shift ;;
            --dry-run)     DRY_RUN=1; shift ;;
            --rollback)    ROLLBACK=1; shift ;;
            -h|--help)     patch_usage; exit 0 ;;
            *)             unknown="$unknown $1"; shift ;;
        esac
    done

    if [ -z "$OUTPUT_FILE" ]; then
        echo "FATAL: --output FILE is required" >&2
        patch_usage
        exit 2
    fi
    [ -n "$unknown" ] && add_warn "ignored unknown arguments:$unknown"
    return 0
}

# Validation that needs the report machinery to be armed already.
patch_validate_args() {
    local ok=0
    if [ -z "$PATCH_ID" ]; then
        add_error "--patch-id is required"
        ok=1
    elif ! [[ "$PATCH_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        add_error "invalid --patch-id '$PATCH_ID' (allowed: letters, digits, dot, underscore, dash)"
        ok=1
    fi
    if [ "$ROLLBACK" -eq 0 ]; then
        case "$MODE" in
            security|all|packages) ;;
            "") add_error "--mode is required (security | all | packages)"; ok=1 ;;
            *)  add_error "invalid --mode '$MODE' (security | all | packages)"; ok=1 ;;
        esac
        if [ "$MODE" = "packages" ] && [ -z "$PACKAGES" ]; then
            add_error "--mode packages requires --packages \"pkg ...\""
            ok=1
        fi
        # package / exclude tokens end up on a command line - be strict
        local tok
        for tok in $PACKAGES $EXCLUDES; do
            if ! [[ "$tok" =~ ^[A-Za-z0-9][A-Za-z0-9.+_:~*?-]*$ ]]; then
                add_error "invalid package specification '$tok'"
                ok=1
            fi
        done
    fi
    if ! is_root; then
        add_error "patching requires root privileges"
        ok=1
    fi
    return "$ok"
}

patch_state_init() {
    local id="$PATCH_ID"
    if ! [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        id="invalid-id"
    fi
    STATE_DIR="$PROV_BASE/patch/$id"
    if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
        STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/provpatch.XXXXXX" 2>/dev/null || echo "/tmp/provpatch.$$")"
        mkdir -p "$STATE_DIR" 2>/dev/null || true
        add_warn "cannot create $PROV_BASE/patch/$id; using temporary state directory $STATE_DIR (rollback data will not persist)"
    fi
    chmod 0700 "$STATE_DIR" 2>/dev/null || true
    if [ "$ROLLBACK" -eq 1 ]; then
        LOG_FILE="$STATE_DIR/rollback.log"
    else
        LOG_FILE="$STATE_DIR/patch.log"
    fi
    if ! : >> "$LOG_FILE" 2>/dev/null; then
        LOG_FILE="/dev/null"
    fi
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/provpatchw.XXXXXX" 2>/dev/null)"
    if [ -z "$WORK_DIR" ] || [ ! -d "$WORK_DIR" ]; then
        WORK_DIR="$STATE_DIR/work.$$"
        mkdir -p "$WORK_DIR" 2>/dev/null || true
    fi
    UPDATED_TSV="$WORK_DIR/updated.tsv"
    REVERTED_TSV="$WORK_DIR/reverted.tsv"
    : > "$UPDATED_TSV" 2>/dev/null
    : > "$REVERTED_TSV" 2>/dev/null
}

# Only one patch / rollback run per host at a time.
patch_lock_acquire() {
    LOCK_DIR="$PROV_BASE/patch/.lock"
    mkdir -p "$PROV_BASE/patch" 2>/dev/null || true
    local tries=0 pid
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        pid="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
        if [ -n "$pid" ] && is_uint "$pid" && ! kill -0 "$pid" 2>/dev/null; then
            log "removing stale patch lock of dead process $pid"
            rm -rf "$LOCK_DIR" 2>/dev/null
            continue
        fi
        if [ -z "$pid" ] && [ "$tries" -ge 3 ]; then
            rm -rf "$LOCK_DIR" 2>/dev/null
            continue
        fi
        tries=$(( tries + 1 ))
        if [ "$tries" -gt 30 ]; then
            add_error "another patch run (pid ${pid:-unknown}) holds $LOCK_DIR; giving up after 5 minutes"
            return 1
        fi
        sleep 10
    done
    printf '%s\n' "$$" > "$LOCK_DIR/pid" 2>/dev/null
    printf '%s\n' "$PATCH_ID" > "$LOCK_DIR/patch_id" 2>/dev/null
    LOCK_HELD=1
    return 0
}

patch_lock_release() {
    if [ "$LOCK_HELD" -eq 1 ] && [ -n "$LOCK_DIR" ]; then
        rm -rf "$LOCK_DIR" 2>/dev/null || true
        LOCK_HELD=0
    fi
}

# ----------------------------------------------------------------------------
# Report writers
# ----------------------------------------------------------------------------
write_patch_report() {
    local tmp="${OUTPUT_FILE}.tmp.$$"
    mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true
    [ -n "$STARTED_AT" ] || STARTED_AT="$(now_iso)"
    FINISHED_AT="$(now_iso)"
    [ -n "$HOST_NAME" ] || HOST_NAME="$(hostname 2>/dev/null || echo unknown)"
    local mode_out="$MODE"
    [ -n "$mode_out" ] || mode_out="unknown"
    {
        printf '{'
        printf '"schema_version":%d,' "$PATCH_SCHEMA_VERSION"
        printf '"patch_id":%s,' "$(json_str "$PATCH_ID")"
        printf '"hostname":%s,' "$(json_str "$HOST_NAME")"
        printf '"os":{"id":%s,"version":%s},' "$(json_str "$OS_ID")" "$(json_str "$OS_VERSION")"
        printf '"mode":%s,' "$(json_str "$mode_out")"
        printf '"dry_run":%s,' "$(json_bool "$DRY_RUN")"
        printf '"started_at":%s,' "$(json_str "$STARTED_AT")"
        printf '"finished_at":%s,' "$(json_str "$FINISHED_AT")"
        printf '"status":%s,' "$(json_str "$STATUS")"
        printf '"packages_updated":'
        _emit_pkg_changes_json "$UPDATED_TSV"
        printf ','
        printf '"reboot_required":%s,' "$(json_bool "$REBOOT_REQUIRED")"
        printf '"rebooted":false,'
        printf '"transaction_id":%s,' "$(json_str "$TRANSACTION_ID")"
        printf '"pre_check":{"passed":true,"messages":[]},'
        printf '"post_check":{"passed":true,"messages":[]},'
        printf '"errors":'
        _emit_errors_json
        printf '}\n'
    } > "$tmp" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }
    _utf8_clean "$tmp"
    if mv -f "$tmp" "$OUTPUT_FILE" 2>/dev/null; then
        chmod 0644 "$OUTPUT_FILE" 2>/dev/null || true
        REPORT_WRITTEN=1
        # keep a copy with the state for later inspection / rollback
        if [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ] && [ "$OUTPUT_FILE" != "$STATE_DIR/patch_result.json" ]; then
            cp -f "$OUTPUT_FILE" "$STATE_DIR/patch_result.json" 2>/dev/null || true
        fi
        return 0
    fi
    rm -f "$tmp" 2>/dev/null
    return 1
}

write_rollback_report() {
    local tmp="${OUTPUT_FILE}.tmp.$$"
    mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true
    [ -n "$HOST_NAME" ] || HOST_NAME="$(hostname 2>/dev/null || echo unknown)"
    case "$STATUS" in success|partial|failed) ;; *) STATUS="failed" ;; esac
    {
        printf '{'
        printf '"schema_version":%d,' "$PATCH_SCHEMA_VERSION"
        printf '"patch_id":%s,' "$(json_str "$PATCH_ID")"
        printf '"hostname":%s,' "$(json_str "$HOST_NAME")"
        printf '"status":%s,' "$(json_str "$STATUS")"
        printf '"packages_reverted":'
        _emit_pkg_changes_json "$REVERTED_TSV"
        printf ','
        printf '"errors":'
        _emit_errors_json
        printf '}\n'
    } > "$tmp" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }
    _utf8_clean "$tmp"
    if mv -f "$tmp" "$OUTPUT_FILE" 2>/dev/null; then
        chmod 0644 "$OUTPUT_FILE" 2>/dev/null || true
        REPORT_WRITTEN=1
        if [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ]; then
            cp -f "$OUTPUT_FILE" "$STATE_DIR/rollback_result.json" 2>/dev/null || true
        fi
        return 0
    fi
    rm -f "$tmp" 2>/dev/null
    return 1
}

_write_any_report() {
    if [ "$ROLLBACK" -eq 1 ]; then
        write_rollback_report
    else
        write_patch_report
    fi
}

_patch_cleanup() {
    patch_lock_release
    if declare -F distro_cleanup > /dev/null 2>&1; then
        distro_cleanup || true
    fi
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR" 2>/dev/null || true
    fi
}

_patch_on_exit() {
    local rc=$?
    if [ "$REPORT_WRITTEN" -eq 0 ] && [ -n "$OUTPUT_FILE" ]; then
        STATUS="failed"
        add_error "script terminated before completion (exit code $rc)"
        if _write_any_report; then
            rc=0
        else
            echo "FATAL: could not write report to $OUTPUT_FILE" >&2
            rc=3
        fi
    fi
    _patch_cleanup
    exit "$rc"
}

_patch_on_signal() {
    STATUS="failed"
    add_error "interrupted by signal $1; the package manager may have been left mid-transaction"
    exit 0   # EXIT trap writes the report
}

# patch_init "$@" - parse arguments, arm the report traps, create state dir
patch_init() {
    patch_parse_args "$@"
    STARTED_AT="$(now_iso)"
    trap '_patch_on_exit' EXIT
    trap '_patch_on_signal TERM' TERM
    trap '_patch_on_signal INT' INT
    trap '_patch_on_signal HUP' HUP
    patch_state_init
    detect_os
    log "start patch_id=$PATCH_ID mode=$MODE dry_run=$DRY_RUN no_kernel=$NO_KERNEL rollback=$ROLLBACK os=$OS_ID $OS_VERSION"
    log "packages='$PACKAGES' exclude='$EXCLUDES' output=$OUTPUT_FILE state=$STATE_DIR"
}

# patch_finish STATUS - write the report and exit. The exit code is 0 whenever
# the report could be written; callers read the status from the JSON.
patch_finish() {
    STATUS="$1"
    if _write_any_report; then
        log "finished with status=$STATUS; report at $OUTPUT_FILE"
        _patch_cleanup
        trap - EXIT
        exit 0
    fi
    echo "FATAL: could not write report to $OUTPUT_FILE" >&2
    _patch_cleanup
    trap - EXIT
    exit 3
}

# Take the "before" snapshot unless one already exists for this patch id (a
# re-run after a partial failure must keep the original baseline).
ensure_before_snapshot() {
    local f="$STATE_DIR/packages.before"
    if [ -s "$f" ]; then
        log "keeping existing baseline $f"
        return 0
    fi
    if snapshot_packages "$f"; then
        log "baseline snapshot written to $f ($(wc -l < "$f" | tr -d ' ') packages)"
        return 0
    fi
    add_error "could not snapshot installed packages to $f; rollback will not be possible"
    return 1
}

# After patching: snapshot, diff against baseline, fill UPDATED_TSV.
record_after_snapshot() {
    local a="$STATE_DIR/packages.after"
    if ! snapshot_packages "$a"; then
        add_error "could not snapshot installed packages after patching"
        return 1
    fi
    diff_packages "$STATE_DIR/packages.before" "$a" > "$UPDATED_TSV" 2>/dev/null
    cp -f "$UPDATED_TSV" "$STATE_DIR/packages.diff" 2>/dev/null || true
    return 0
}

updated_count() {
    [ -s "$UPDATED_TSV" ] || { printf '0'; return 0; }
    awk 'length($0) > 0 { n++ } END { print n + 0 }' "$UPDATED_TSV"
}

# ----------------------------------------------------------------------------
# Rollback bookkeeping (shared by deb and rpm)
# ----------------------------------------------------------------------------
# rollback_finalize - expects $STATE_DIR/packages.before, rollback.pre and
# rollback.post; fills REVERTED_TSV, records what is still different and sets
# STATUS to success | partial | failed.
rollback_finalize() {
    local before="$STATE_DIR/packages.before" pre="$STATE_DIR/rollback.pre" post="$STATE_DIR/rollback.post"
    if ! snapshot_packages "$post"; then
        add_error "could not snapshot packages after rollback"
        STATUS="failed"
        return 0
    fi
    diff_packages "$pre" "$post" > "$REVERTED_TSV" 2>/dev/null
    local reverted remaining_f="$WORK_DIR/remaining.tsv" remaining
    reverted="$(awk 'length($0) > 0 { n++ } END { print n + 0 }' "$REVERTED_TSV" 2>/dev/null)"
    packages_missing "$before" "$post" > "$remaining_f" 2>/dev/null
    remaining="$(awk 'length($0) > 0 { n++ } END { print n + 0 }' "$remaining_f" 2>/dev/null)"
    reverted="$(uint_or "$reverted" 0)"
    remaining="$(uint_or "$remaining" 0)"

    if [ "$remaining" -gt 0 ]; then
        local n=0 name wanted current
        while IFS="$_TAB" read -r name wanted current; do
            n=$(( n + 1 ))
            if [ "$n" -le 40 ]; then
                add_error "could not revert $name to $wanted (currently ${current:-not installed})"
            fi
        done < "$remaining_f"
        if [ "$remaining" -gt 40 ]; then
            add_error "... and $(( remaining - 40 )) more package(s) could not be reverted"
        fi
    fi

    # packages that the patch run newly installed (new kernels, new deps) and
    # that are still present are reported, but do not make the rollback fail
    local extra
    extra="$(awk -F'\t' -v beforef="$before" '
        BEGIN { while ((getline l < beforef) > 0) { split(l, a, "\t"); names[a[1]] = 1; pairs[a[1] SUBSEP a[2]] = 1 } close(beforef) }
        NF >= 2 && !(($1 SUBSEP $2) in pairs) { printf "%s=%s ", $1, $2; n++ }
        n >= 15 { exit }' "$post" 2>/dev/null)"
    if [ -n "$extra" ]; then
        add_note "package versions installed that were not part of the baseline (left in place): $extra"
    fi

    if [ "$remaining" -eq 0 ]; then
        STATUS="success"
    elif [ "$reverted" -gt 0 ]; then
        STATUS="partial"
    else
        STATUS="failed"
    fi
    log "rollback result: reverted=$reverted remaining=$remaining status=$STATUS"
    return 0
}

# =============================================================================
# Enterprise Linux (yum / dnf) engine
# =============================================================================
EL_PM=""
EL_SECMETA="unknown"
EL_FILTER_ARGS=()      # --exclude=... arguments
EL_SELECT_ARGS=()      # package names / --advisory=... for mode=packages
EL_KERNEL_GLOBS="kernel kernel-* kernel-uek* kmod-kvdo kernel-rt*"

el_detect_pm() {
    if have dnf; then
        EL_PM="dnf"
    elif have yum; then
        EL_PM="yum"
    else
        add_error "neither dnf nor yum found"
        return 1
    fi
    return 0
}

# Wait for another yum/dnf/rpm process to finish.
el_wait_for_lock() {
    local waited=0 max="${1:-600}" holder
    while :; do
        holder="$(pgrep -x -d ' ' 'yum|dnf|rpm|dnf-automatic|yum-cron|packagekitd' 2>/dev/null)"
        # packagekitd idles permanently on desktops; only a yum.pid matters there
        if [ -z "$holder" ] || [ "$holder" = "$(pgrep -x -d ' ' packagekitd 2>/dev/null)" ]; then
            if [ -e /var/run/yum.pid ]; then
                local p
                p="$(cat /var/run/yum.pid 2>/dev/null)"
                if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
                    holder="$p"
                else
                    return 0
                fi
            else
                return 0
            fi
        fi
        if [ "$waited" -ge "$max" ]; then
            add_error "package manager is busy (pids: $holder) after waiting ${max}s"
            return 1
        fi
        [ $(( waited % 60 )) -eq 0 ] && log "waiting for running package manager (pids: $holder)"
        sleep 10
        waited=$(( waited + 10 ))
    done
}

el_refresh_cache() {
    local rc
    if [ "$EL_PM" = "yum" ]; then
        run_logged "$PM_TIMEOUT" yum -q clean expire-cache
        run_logged "$PM_TIMEOUT" yum -q makecache fast
        rc=$?
        if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
            run_logged "$PM_TIMEOUT" yum -q makecache
            rc=$?
        fi
    else
        run_logged "$PM_TIMEOUT" dnf -q makecache --refresh
        rc=$?
    fi
    if [ "$rc" -eq 124 ]; then
        add_warn "$EL_PM makecache timed out after ${PM_TIMEOUT}s; continuing with cached metadata"
    elif [ "$rc" -ne 0 ]; then
        add_warn "$EL_PM makecache failed (rc=$rc): $(log_error_tail); continuing with cached metadata"
    fi
    return 0
}

el_enabled_repo_count() {
    local n
    n="$(run_to "$PM_TIMEOUT" "$EL_PM" -q repolist enabled 2>/dev/null | awk 'NR > 1 && NF > 0 && $1 !~ /^(repolist:|Loaded|Loading|\*)/ { n++ } END { print n + 0 }')"
    uint_or "$n" 0
}

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

# Most recent yum/dnf history transaction id (empty when none)
el_last_tid() {
    run_to 120 "$EL_PM" history list 2>/dev/null \
        | awk -F'|' '$1 ~ /^[[:space:]]*[0-9]+[[:space:]]*$/ { gsub(/[[:space:]]/, "", $1); print $1; exit }'
}

# Build --exclude arguments from EXCLUDES and --no-kernel
el_build_filters() {
    EL_FILTER_ARGS=()
    local x
    for x in $EXCLUDES; do
        EL_FILTER_ARGS[${#EL_FILTER_ARGS[@]}]="--exclude=$x"
    done
    if [ "$NO_KERNEL" -eq 1 ]; then
        for x in $EL_KERNEL_GLOBS; do
            EL_FILTER_ARGS[${#EL_FILTER_ARGS[@]}]="--exclude=$x"
        done
    fi
}

# Split PACKAGES into advisory ids and package names; unknown packages are
# reported and skipped. Returns 1 when nothing usable is left.
el_build_selection() {
    EL_SELECT_ARGS=()
    local p usable=0
    for p in $PACKAGES; do
        if [[ "$p" =~ ^(RH|CE|EL|RL|AL|FEDORA-EPEL-|CL)[A-Z]*-?[0-9]{4}[:-][0-9A-Za-z]+$ ]] || [[ "$p" =~ ^[A-Z]{2,5}[SBE]A-[0-9]{4}[:-][0-9]+$ ]]; then
            EL_SELECT_ARGS[${#EL_SELECT_ARGS[@]}]="--advisory=$p"
            usable=$(( usable + 1 ))
            continue
        fi
        case "$p" in
            *'*'*|*'?'*)
                EL_SELECT_ARGS[${#EL_SELECT_ARGS[@]}]="$p"
                usable=$(( usable + 1 ))
                ;;
            *)
                if rpm -q "$p" > /dev/null 2>&1; then
                    EL_SELECT_ARGS[${#EL_SELECT_ARGS[@]}]="$p"
                    usable=$(( usable + 1 ))
                else
                    add_warn "package '$p' is not installed; skipped (patching never installs new top-level packages)"
                fi
                ;;
        esac
    done
    [ "$usable" -gt 0 ]
}

# Parse check-update output (stdin) into: name.arch \t version \t repo
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
                if (n == 0 && $i !~ /\.(x86_64|i[3-6]86|noarch|aarch64|ppc64le|ppc64|s390x|armv7hl|src)$/) break
                n++
                buf[n] = $i
                if (n == 3) { print buf[1], buf[2], buf[3]; flush() }
            }
        }'
}

el_reboot_required() {
    local rc
    if is_container; then
        REBOOT_REQUIRED="false"
        return 0
    fi
    if have needs-restarting; then
        run_to 120 needs-restarting -r > /dev/null 2>&1
        rc=$?
        case "$rc" in
            0) REBOOT_REQUIRED="false"; return 0 ;;
            1) REBOOT_REQUIRED="true"; return 0 ;;
        esac
    elif [ "$EL_PM" = "dnf" ] && run_to 60 dnf -q needs-restarting --help > /dev/null 2>&1; then
        run_to 120 dnf -q needs-restarting -r > /dev/null 2>&1
        rc=$?
        case "$rc" in
            0) REBOOT_REQUIRED="false"; return 0 ;;
            1) REBOOT_REQUIRED="true"; return 0 ;;
        esac
    fi
    # fallback: newest installed kernel differs from the running one, or core
    # libraries were part of this transaction
    local running newest pkgs
    running="$(uname -r)"
    case "$running" in
        *uek*) pkgs="kernel-uek kernel-uek-core" ;;
        *)     pkgs="kernel kernel-core" ;;
    esac
    # shellcheck disable=SC2086
    newest="$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' $pkgs 2>/dev/null | grep -v 'is not installed' | sort -V | tail -n1)"
    if [ -n "$newest" ] && [ "$newest" != "$running" ]; then
        REBOOT_REQUIRED="true"
        return 0
    fi
    if [ -s "$UPDATED_TSV" ] && awk -F'\t' '$1 ~ /^(glibc|systemd|dbus|dbus-broker|openssl-libs|linux-firmware|microcode_ctl|gnutls)$/ { f = 1 } END { exit f ? 0 : 1 }' "$UPDATED_TSV"; then
        REBOOT_REQUIRED="true"
        return 0
    fi
    REBOOT_REQUIRED="false"
}

# The actual update. Expects EL_PM, MODE, filters. Sets STATUS-relevant state
# and returns the package manager's exit code (0 for dry-run success).
el_patch_run() {
    local sec=0
    local -a sel=()

    el_build_filters
    case "$MODE" in
        security)
            if el_has_security_metadata; then
                sec=1
            else
                add_warn "enabled repositories ship no updateinfo (security errata) metadata; '--security' would be a silent no-op, so ALL available updates are applied instead"
            fi
            ;;
        all) ;;
        packages)
            if ! el_build_selection; then
                add_error "none of the requested packages/advisories can be updated on this host: $PACKAGES"
                return 90
            fi
            ;;
    esac
    [ "$sec" -eq 1 ] && sel[${#sel[@]}]="--security"
    if [ "${#EL_SELECT_ARGS[@]}" -gt 0 ]; then
        sel=( ${sel[@]+"${sel[@]}"} "${EL_SELECT_ARGS[@]}" )
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        local cu="$WORK_DIR/check_update.out" rc
        run_to "$PM_TIMEOUT" "$EL_PM" -q check-update ${sel[@]+"${sel[@]}"} ${EL_FILTER_ARGS[@]+"${EL_FILTER_ARGS[@]}"} > "$cu" 2>> "$LOG_FILE"
        rc=$?
        cat "$cu" >> "$LOG_FILE" 2>/dev/null || true
        case "$rc" in
            0) log "dry-run: nothing to update"; return 0 ;;
            100)
                local inst="$WORK_DIR/installed.tsv"
                rpm -qa --qf '%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort -t "$_TAB" -k1,1 -k2,2V > "$inst"
                el_parse_check_update < "$cu" | awk -F'\t' -v OFS='\t' -v instf="$inst" '
                    BEGIN { while ((getline l < instf) > 0) { split(l, a, "\t"); inst[a[1]] = a[2] } close(instf) }
                    NF >= 2 {
                        key = $1; name = key; sub(/\.[^.]+$/, "", name)
                        cur = (key in inst) ? inst[key] : ""; sub(/^0:/, "", cur)
                        cand = $2; sub(/^0:/, "", cand)
                        print name, cur, cand
                    }' > "$UPDATED_TSV"
                return 0 ;;
            124) add_error "$EL_PM check-update timed out after ${PM_TIMEOUT}s"; return 124 ;;
            *)   add_error "$EL_PM check-update failed (rc=$rc): $(log_error_tail)"; return "$rc" ;;
        esac
    fi

    local tid_before tid_after rc
    tid_before="$(el_last_tid)"
    printf '%s\n' "${tid_before:-}" > "$STATE_DIR/transaction_id.prev" 2>/dev/null || true

    local shown=""
    [ "${#sel[@]}" -gt 0 ] && shown="${sel[*]}"
    [ "${#EL_FILTER_ARGS[@]}" -gt 0 ] && shown="$shown ${EL_FILTER_ARGS[*]}"
    log "running: $EL_PM -y update $shown"
    run_logged "$TXN_TIMEOUT" "$EL_PM" -y update ${sel[@]+"${sel[@]}"} ${EL_FILTER_ARGS[@]+"${EL_FILTER_ARGS[@]}"}
    rc=$?

    if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && [ "$EL_PM" = "dnf" ]; then
        # typical recoverable cause: a single package with broken dependencies
        if tail -n 80 "$LOG_FILE" 2>/dev/null | grep -qE '(Problem|nothing provides|conflicting requests|cannot install the best update candidate)'; then
            add_warn "dependency problems with the best candidates; retrying with --nobest --skip-broken"
            run_logged "$TXN_TIMEOUT" dnf -y update --nobest --skip-broken ${sel[@]+"${sel[@]}"} ${EL_FILTER_ARGS[@]+"${EL_FILTER_ARGS[@]}"}
            rc=$?
        fi
    elif [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && [ "$EL_PM" = "yum" ]; then
        if tail -n 80 "$LOG_FILE" 2>/dev/null | grep -qE '(Requires:|You could try using --skip-broken)'; then
            add_warn "dependency problems; retrying with --skip-broken"
            run_logged "$TXN_TIMEOUT" yum -y update --skip-broken ${sel[@]+"${sel[@]}"} ${EL_FILTER_ARGS[@]+"${EL_FILTER_ARGS[@]}"}
            rc=$?
        fi
    fi

    tid_after="$(el_last_tid)"
    if [ -n "$tid_after" ] && [ "$tid_after" != "$tid_before" ]; then
        TRANSACTION_ID="$tid_after"
        printf '%s\n' "$TRANSACTION_ID" > "$STATE_DIR/transaction_id" 2>/dev/null || add_warn "could not persist transaction id $TRANSACTION_ID"
        printf '%s\n' "$EL_PM" > "$STATE_DIR/pkg_manager" 2>/dev/null || true
        run_logged 120 "$EL_PM" history info "$TRANSACTION_ID" || true
        if [ -n "$tid_before" ] && is_uint "$tid_before" && is_uint "$tid_after" && [ $(( tid_after - tid_before )) -gt 1 ]; then
            add_warn "more than one $EL_PM transaction was recorded during patching (ids $(( tid_before + 1 ))..$tid_after); rollback only undoes $tid_after"
        fi
    fi

    if [ "$rc" -eq 124 ]; then
        add_error "$EL_PM update timed out after ${TXN_TIMEOUT}s; the transaction may be incomplete (see $LOG_FILE)"
    elif [ "$rc" -ne 0 ]; then
        add_error "$EL_PM update failed (rc=$rc): $(log_error_tail)"
    fi
    return "$rc"
}

# Complete flow shared by patch_centos.sh and patch_rhel.sh once their distro
# specific preparation is done.
el_patch_main() {
    el_wait_for_lock 600 || patch_finish failed
    el_refresh_cache

    if [ "$(el_enabled_repo_count)" -eq 0 ]; then
        add_error "no enabled package repositories; nothing can be updated"
        patch_finish failed
    fi

    if [ "$DRY_RUN" -eq 0 ]; then
        ensure_before_snapshot || patch_finish failed
    fi

    local rc
    el_patch_run
    rc=$?

    if [ "$DRY_RUN" -eq 1 ]; then
        if [ "$rc" -ne 0 ]; then
            patch_finish failed
        fi
        patch_finish dry_run
    fi

    record_after_snapshot || true
    el_reboot_required

    if [ "$rc" -ne 0 ]; then
        patch_finish failed
    fi
    if [ "$(updated_count)" -eq 0 ]; then
        patch_finish no_changes
    fi
    patch_finish success
}

# yum/dnf rollback: "history undo <transaction_id>", then a best effort
# downgrade for whatever is still newer than the baseline.
el_rollback_main() {
    local before="$STATE_DIR/packages.before" pre="$STATE_DIR/rollback.pre"
    if [ ! -s "$before" ]; then
        add_error "no baseline ($before) found for patch id '$PATCH_ID'; nothing to roll back to"
        patch_finish failed
    fi
    el_wait_for_lock 600 || patch_finish failed
    if ! snapshot_packages "$pre"; then
        add_error "could not snapshot current packages before rollback"
        patch_finish failed
    fi

    local tid=""
    [ -r "$STATE_DIR/transaction_id" ] && tid="$(head -n1 "$STATE_DIR/transaction_id" 2>/dev/null | tr -cd '0-9')"

    if [ -z "$tid" ]; then
        if [ -z "$(packages_missing "$before" "$pre" 2>/dev/null)" ]; then
            add_note "no transaction id recorded and installed packages already match the baseline; nothing to undo"
            rollback_finalize
            patch_finish "$STATUS"
        fi
        add_warn "no yum/dnf transaction id recorded for patch id '$PATCH_ID'; falling back to package downgrades"
    else
        log "undoing $EL_PM transaction $tid"
        local rc
        run_logged "$TXN_TIMEOUT" "$EL_PM" -y history undo "$tid"
        rc=$?
        if [ "$rc" -eq 124 ]; then
            add_error "$EL_PM history undo $tid timed out after ${TXN_TIMEOUT}s"
        elif [ "$rc" -ne 0 ]; then
            add_warn "$EL_PM history undo $tid failed (rc=$rc): $(log_error_tail)"
        fi
    fi

    # Anything still not at the baseline version? Try explicit downgrades.
    local nowf="$WORK_DIR/now.tsv" missing="$WORK_DIR/missing.tsv"
    if snapshot_packages "$nowf"; then
        packages_missing "$before" "$nowf" > "$missing" 2>/dev/null
        if [ -s "$missing" ]; then
            local -a specs=()
            local name wanted current base arch ver
            while IFS="$_TAB" read -r name wanted current; do
                [ -n "$name" ] || continue
                base="${name%.*}"
                arch="${name##*.}"
                case "$base" in
                    kernel|kernel-core|kernel-modules|kernel-modules-core|kernel-modules-extra|kernel-uek|kernel-uek-core|kernel-devel)
                        # install-only packages are never downgraded; the old
                        # version is reinstalled alongside instead
                        continue ;;
                esac
                ver="${wanted#0:}"
                specs[${#specs[@]}]="${base}-${ver}.${arch}"
            done < "$missing"
            if [ "${#specs[@]}" -gt 0 ]; then
                log "attempting explicit downgrade of ${#specs[@]} package(s)"
                if ! run_logged "$TXN_TIMEOUT" "$EL_PM" -y downgrade "${specs[@]}"; then
                    add_warn "bulk downgrade failed: $(log_error_tail); retrying package by package"
                    local s
                    for s in "${specs[@]}"; do
                        run_logged "$PM_TIMEOUT" "$EL_PM" -y downgrade "$s" || true
                    done
                fi
            fi
        fi
    fi

    rollback_finalize
    el_reboot_required
    if [ "$REBOOT_REQUIRED" = "true" ]; then
        add_note "a reboot is required to finish the rollback (kernel or core libraries changed)"
    fi
    if [ "$(uname -r)" != "$(cat "$STATE_DIR/kernel.before" 2>/dev/null || uname -r)" ]; then
        add_note "running kernel $(uname -r) differs from the pre-patch kernel $(cat "$STATE_DIR/kernel.before" 2>/dev/null); select the old kernel at boot (grubby --set-default) if required"
    fi
    patch_finish "$STATUS"
}

# ----------------------------------------------------------------------------
# Direct execution: snapshot / diff utility modes
# ----------------------------------------------------------------------------
_patch_common_cli() {
    case "${1-}" in
        --snapshot)
            local file="${2-}" if_missing=0
            [ "${3-}" = "--if-missing" ] && if_missing=1
            if [ -z "$file" ]; then
                echo "usage: patch_common.sh --snapshot FILE [--if-missing]" >&2
                return 2
            fi
            if [ "$if_missing" -eq 1 ] && [ -s "$file" ]; then
                echo "snapshot $file already exists; kept"
                return 0
            fi
            if snapshot_packages "$file"; then
                echo "snapshot written to $file ($(wc -l < "$file" | tr -d ' ') packages)"
                return 0
            fi
            echo "ERROR: could not write package snapshot to $file" >&2
            return 1
            ;;
        --diff)
            if [ -z "${2-}" ] || [ -z "${3-}" ]; then
                echo "usage: patch_common.sh --diff BEFORE AFTER" >&2
                return 2
            fi
            diff_packages "$2" "$3"
            return $?
            ;;
        *)
            echo "patch_common.sh is a library; direct modes: --snapshot FILE [--if-missing] | --diff BEFORE AFTER" >&2
            return 2
            ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    _patch_common_cli "$@"
    exit $?
fi
