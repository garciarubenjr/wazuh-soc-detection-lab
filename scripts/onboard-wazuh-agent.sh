#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Wazuh Agent Onboarding
#
# Purpose:
#   Safely install, enroll, start, and validate a Wazuh agent on
#   Debian/Ubuntu endpoints.
#
# Fresh install:
#   sudo bash scripts/onboard-wazuh-agent.sh \
#       --manager 192.168.10.100
#
# Custom name/group:
#   sudo bash scripts/onboard-wazuh-agent.sh \
#       --manager 192.168.10.100 \
#       --name web-server-01 \
#       --group linux-servers
#
# Re-enroll an EXISTING agent:
#   sudo bash scripts/onboard-wazuh-agent.sh \
#       --manager 192.168.10.100 \
#       --force-reenroll
#
# If the Wazuh manager does not require an enrollment password:
#   sudo bash scripts/onboard-wazuh-agent.sh \
#       --manager 192.168.10.100 \
#       --no-enrollment-password
#
###############################################################################

OSSEC_DIR="/var/ossec"
OSSEC_CONF="${OSSEC_DIR}/etc/ossec.conf"
CLIENT_KEYS="${OSSEC_DIR}/etc/client.keys"
AUTHD_PASS="${OSSEC_DIR}/etc/authd.pass"

WAZUH_REPO_FILE="/etc/apt/sources.list.d/wazuh.list"
WAZUH_KEYRING="/usr/share/keyrings/wazuh.gpg"

MANAGER=""
AGENT_NAME="$(hostname -s)"
AGENT_GROUP="default"

COMM_PORT="1514"
ENROLL_PORT="1515"

PACKAGE_VERSION=""

FORCE_REENROLL=false
REQUIRE_ENROLL_PASSWORD=true
HOLD_PACKAGE=true

ENROLL_PASS="${WAZUH_ENROLLMENT_PASSWORD:-}"

CONF_BACKUP=""
KEY_BACKUP=""
AUTHD_PASS_BACKUP=""

AGENT_WAS_INSTALLED=false

###############################################################################
# Logging
###############################################################################

info() {
    printf '[+] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*" >&2
}

die() {
    printf '[-] %s\n' "$*" >&2
    exit 1
}

###############################################################################
# Usage
###############################################################################

usage() {
    cat <<'EOF'
Usage:

  sudo bash scripts/onboard-wazuh-agent.sh --manager HOST [options]

Required:

  --manager HOST
      Wazuh manager IP address or DNS name.

Optional:

  --name NAME
      Agent name.
      Default: system hostname

  --group GROUP
      Existing Wazuh group assigned during enrollment.
      Default: default

  --comm-port PORT
      Wazuh agent communication port.
      Default: 1514

  --enroll-port PORT
      Wazuh enrollment port.
      Default: 1515

  --package-version VERSION
      Install an exact wazuh-agent package version.
      Example: 4.14.7-1

  --force-reenroll
      Explicitly replace an existing agent enrollment.

  --no-enrollment-password
      Enroll without a manager enrollment password.

  --no-hold
      Do not place wazuh-agent on APT hold after installation.

  -h, --help
      Show this help.

Password handling:

  By default, the script securely prompts for the Wazuh enrollment password.

  It may alternatively be provided through:

      WAZUH_ENROLLMENT_PASSWORD

  The password is not accepted as a command-line argument.

Examples:

  sudo bash scripts/onboard-wazuh-agent.sh \
      --manager 192.168.10.100

  sudo bash scripts/onboard-wazuh-agent.sh \
      --manager wazuh-manager.lab.local \
      --name web-server-01 \
      --group linux-servers

EOF
}

###############################################################################
# Argument Parsing
###############################################################################

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --manager)
                [[ -n "${2:-}" ]] || die "--manager requires a value."
                MANAGER="$2"
                shift 2
                ;;

            --name)
                [[ -n "${2:-}" ]] || die "--name requires a value."
                AGENT_NAME="$2"
                shift 2
                ;;

            --group)
                [[ -n "${2:-}" ]] || die "--group requires a value."
                AGENT_GROUP="$2"
                shift 2
                ;;

            --comm-port)
                [[ -n "${2:-}" ]] || die "--comm-port requires a value."
                COMM_PORT="$2"
                shift 2
                ;;

            --enroll-port)
                [[ -n "${2:-}" ]] || die "--enroll-port requires a value."
                ENROLL_PORT="$2"
                shift 2
                ;;

            --package-version)
                [[ -n "${2:-}" ]] || die "--package-version requires a value."
                PACKAGE_VERSION="$2"
                shift 2
                ;;

            --force-reenroll)
                FORCE_REENROLL=true
                shift
                ;;

            --no-enrollment-password)
                REQUIRE_ENROLL_PASSWORD=false
                shift
                ;;

            --no-hold)
                HOLD_PACKAGE=false
                shift
                ;;

            -h|--help)
                usage
                exit 0
                ;;

            *)
                die "Unknown argument: $1"
                ;;
        esac
    done
}

###############################################################################
# Basic Validation
###############################################################################

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "Run this script as root with sudo."
}

validate_inputs() {
    [[ -n "${MANAGER}" ]] || die "--manager is required."

    [[ "${COMM_PORT}" =~ ^[0-9]+$ ]] \
        || die "Invalid communication port."

    [[ "${ENROLL_PORT}" =~ ^[0-9]+$ ]] \
        || die "Invalid enrollment port."

    (( COMM_PORT >= 1 && COMM_PORT <= 65535 )) \
        || die "Communication port is outside valid range."

    (( ENROLL_PORT >= 1 && ENROLL_PORT <= 65535 )) \
        || die "Enrollment port is outside valid range."

    # Wazuh agent names support letters, numbers, dots, underscores, hyphens.
    [[ "${AGENT_NAME}" =~ ^[A-Za-z0-9._-]{2,}$ ]] \
        || die "Invalid agent name: ${AGENT_NAME}"

    [[ "${AGENT_GROUP}" =~ ^[A-Za-z0-9._,-]+$ ]] \
        || die "Invalid agent group: ${AGENT_GROUP}"

    if [[ "${MANAGER}" =~ [[:space:]] ]]; then
        die "Manager address must not contain whitespace."
    fi
}

###############################################################################
# OS Validation
###############################################################################

validate_os() {
    [[ -f /etc/os-release ]] \
        || die "Unable to determine operating system."

    # shellcheck disable=SC1091
    source /etc/os-release

    case "${ID:-}" in
        ubuntu|debian)
            ;;
        *)
            die "This script currently supports Debian/Ubuntu systems only."
            ;;
    esac

    info "Detected operating system: ${PRETTY_NAME:-${ID}}"
}

###############################################################################
# Enrollment Password
###############################################################################

get_enrollment_password() {
    if [[ "${REQUIRE_ENROLL_PASSWORD}" == false ]]; then
        info "Enrollment password disabled by explicit request."
        return
    fi

    if [[ -n "${ENROLL_PASS}" ]]; then
        info "Enrollment password supplied through environment."
        return
    fi

    [[ -r /dev/tty ]] \
        || die "Unable to securely prompt for enrollment password."

    read \
        -r \
        -s \
        -p "Wazuh enrollment password: " \
        ENROLL_PASS \
        </dev/tty

    printf '\n' >/dev/tty

    [[ -n "${ENROLL_PASS}" ]] \
        || die "Enrollment password cannot be empty."
}

###############################################################################
# Network Preflight
###############################################################################

check_dns() {
    info "Resolving manager: ${MANAGER}"

    if ! getent hosts "${MANAGER}" >/dev/null 2>&1; then
        die "Could not resolve or locate manager: ${MANAGER}"
    fi
}

check_tcp_port() {
    local host="$1"
    local port="$2"
    local description="$3"

    info "Testing ${description}: ${host}:${port}"

    if timeout 4 \
        bash -c "exec 3<>/dev/tcp/${host}/${port}" \
        2>/dev/null; then

        info "${description} reachable."
    else
        die "${description} is not reachable on ${host}:${port}"
    fi
}

preflight_connectivity() {
    check_dns

    check_tcp_port \
        "${MANAGER}" \
        "${ENROLL_PORT}" \
        "Wazuh enrollment service"

    check_tcp_port \
        "${MANAGER}" \
        "${COMM_PORT}" \
        "Wazuh agent communication service"
}

###############################################################################
# Dependencies
###############################################################################

install_dependencies() {
    info "Installing required packages..."

    apt-get update

    DEBIAN_FRONTEND=noninteractive \
        apt-get install -y \
            ca-certificates \
            curl \
            gnupg \
            apt-transport-https \
            lsb-release \
            iproute2
}

###############################################################################
# Wazuh Repository
###############################################################################

install_wazuh_repository() {
    info "Configuring official Wazuh APT repository..."

    local tmp_key

    tmp_key="$(mktemp)"

    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        "https://packages.wazuh.com/key/GPG-KEY-WAZUH" \
        -o "${tmp_key}"

    gpg \
        --batch \
        --yes \
        --dearmor \
        --output "${WAZUH_KEYRING}" \
        "${tmp_key}"

    rm -f "${tmp_key}"

    chmod 0644 "${WAZUH_KEYRING}"

    cat > "${WAZUH_REPO_FILE}" <<EOF
deb [signed-by=${WAZUH_KEYRING}] https://packages.wazuh.com/4.x/apt/ stable main
EOF

    apt-get update
}

###############################################################################
# Existing Installation Detection
###############################################################################

detect_existing_agent() {
    if dpkg-query \
        -W \
        -f='${Status}' \
        wazuh-agent \
        2>/dev/null \
        | grep -q "install ok installed"; then

        AGENT_WAS_INSTALLED=true

        info "Existing wazuh-agent installation detected."

        if [[ "${FORCE_REENROLL}" != true ]]; then
            cat >&2 <<EOF

The Wazuh agent is already installed.

No enrollment information was changed.

If you intentionally want to replace its current enrollment,
run this script again with:

  --force-reenroll

EOF
            exit 0
        fi

        warn "Explicit re-enrollment requested."
    fi
}

###############################################################################
# Backup Existing State
###############################################################################

backup_existing_state() {
    local timestamp

    timestamp="$(date +%Y%m%d-%H%M%S)"

    if [[ -f "${OSSEC_CONF}" ]]; then
        CONF_BACKUP="${OSSEC_CONF}.bak.${timestamp}"

        cp -a \
            "${OSSEC_CONF}" \
            "${CONF_BACKUP}"

        info "Configuration backup: ${CONF_BACKUP}"
    fi

    if [[ -f "${CLIENT_KEYS}" ]]; then
        KEY_BACKUP="${CLIENT_KEYS}.bak.${timestamp}"

        cp -a \
            "${CLIENT_KEYS}" \
            "${KEY_BACKUP}"

        chmod 0600 "${KEY_BACKUP}"

        info "Enrollment key backup: ${KEY_BACKUP}"
    fi
}

###############################################################################
# Fresh Agent Installation
###############################################################################

install_agent() {
    info "Installing Wazuh agent..."

    export WAZUH_MANAGER="${MANAGER}"
    export WAZUH_REGISTRATION_SERVER="${MANAGER}"
    export WAZUH_AGENT_NAME="${AGENT_NAME}"
    export WAZUH_AGENT_GROUP="${AGENT_GROUP}"

    if [[ "${REQUIRE_ENROLL_PASSWORD}" == true ]]; then
        export WAZUH_REGISTRATION_PASSWORD="${ENROLL_PASS}"
    fi

    if [[ -n "${PACKAGE_VERSION}" ]]; then
        info "Requested package version: ${PACKAGE_VERSION}"

        if ! apt-cache madison wazuh-agent \
            | awk '{print $3}' \
            | grep -Fxq "${PACKAGE_VERSION}"; then

            die "Requested Wazuh package version is unavailable: ${PACKAGE_VERSION}"
        fi

        DEBIAN_FRONTEND=noninteractive \
            apt-get install -y \
            "wazuh-agent=${PACKAGE_VERSION}"
    else
        DEBIAN_FRONTEND=noninteractive \
            apt-get install -y \
            wazuh-agent
    fi

    unset WAZUH_MANAGER
    unset WAZUH_REGISTRATION_SERVER
    unset WAZUH_AGENT_NAME
    unset WAZUH_AGENT_GROUP
    unset WAZUH_REGISTRATION_PASSWORD || true

    [[ -x "${OSSEC_DIR}/bin/wazuh-agentd" ]] \
        || die "Wazuh agent installation did not complete successfully."
}

###############################################################################
# Temporary Password File for Explicit Re-enrollment
###############################################################################

prepare_auth_password_file() {
    [[ "${REQUIRE_ENROLL_PASSWORD}" == true ]] || return

    if [[ -f "${AUTHD_PASS}" ]]; then
        AUTHD_PASS_BACKUP="${AUTHD_PASS}.onboarding-backup"

        cp -a \
            "${AUTHD_PASS}" \
            "${AUTHD_PASS_BACKUP}"
    fi

    umask 077

    printf '%s\n' "${ENROLL_PASS}" \
        > "${AUTHD_PASS}"

    chmod 0600 "${AUTHD_PASS}"
}

restore_auth_password_file() {
    rm -f "${AUTHD_PASS}"

    if [[ -n "${AUTHD_PASS_BACKUP}" \
        && -f "${AUTHD_PASS_BACKUP}" ]]; then

        mv \
            "${AUTHD_PASS_BACKUP}" \
            "${AUTHD_PASS}"
    fi
}

###############################################################################
# Update Manager Address for Existing Installations
###############################################################################

update_existing_manager_config() {
    [[ -f "${OSSEC_CONF}" ]] \
        || die "Missing Wazuh configuration: ${OSSEC_CONF}"

    info "Updating Wazuh manager connection configuration..."

    python3 - \
        "${OSSEC_CONF}" \
        "${MANAGER}" \
        "${COMM_PORT}" <<'PY'
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

path = Path(sys.argv[1])
manager = escape(sys.argv[2])
port = sys.argv[3]

text = path.read_text()

client_match = re.search(
    r"<client\b[^>]*>.*?</client>",
    text,
    flags=re.DOTALL
)

if not client_match:
    raise SystemExit(
        "Could not locate <client> section in ossec.conf"
    )

client = client_match.group(0)

server_match = re.search(
    r"<server\b[^>]*>.*?</server>",
    client,
    flags=re.DOTALL
)

if not server_match:
    raise SystemExit(
        "Could not locate <server> section in <client>"
    )

server = server_match.group(0)

if re.search(r"<address>.*?</address>", server, flags=re.DOTALL):
    server = re.sub(
        r"<address>.*?</address>",
        f"<address>{manager}</address>",
        server,
        count=1,
        flags=re.DOTALL
    )
else:
    server = server.replace(
        "<server>",
        f"<server>\n      <address>{manager}</address>",
        1
    )

if re.search(r"<port>.*?</port>", server, flags=re.DOTALL):
    server = re.sub(
        r"<port>.*?</port>",
        f"<port>{port}</port>",
        server,
        count=1,
        flags=re.DOTALL
    )
else:
    server = server.replace(
        "</server>",
        f"      <port>{port}</port>\n    </server>",
        1
    )

if re.search(r"<protocol>.*?</protocol>", server, flags=re.DOTALL):
    server = re.sub(
        r"<protocol>.*?</protocol>",
        "<protocol>tcp</protocol>",
        server,
        count=1,
        flags=re.DOTALL
    )

client = (
    client[:server_match.start()]
    + server
    + client[server_match.end():]
)

text = (
    text[:client_match.start()]
    + client
    + text[client_match.end():]
)

path.write_text(text)
PY
}

###############################################################################
# Explicit Re-enrollment
###############################################################################

reenroll_agent() {
    info "Stopping existing Wazuh agent..."

    systemctl stop wazuh-agent || true

    backup_existing_state

    update_existing_manager_config

    info "Removing current enrollment key..."

    rm -f "${CLIENT_KEYS}"

    prepare_auth_password_file

    local args=(
        -m "${MANAGER}"
        -p "${ENROLL_PORT}"
        -A "${AGENT_NAME}"
    )

    if [[ -n "${AGENT_GROUP}" ]]; then
        args+=(
            -G "${AGENT_GROUP}"
        )
    fi

    info "Requesting new enrollment key..."

    if ! "${OSSEC_DIR}/bin/agent-auth" "${args[@]}"; then
        restore_auth_password_file

        warn "Re-enrollment failed."

        if [[ -n "${CONF_BACKUP}" && -f "${CONF_BACKUP}" ]]; then
            cp -a \
                "${CONF_BACKUP}" \
                "${OSSEC_CONF}"
        fi

        if [[ -n "${KEY_BACKUP}" && -f "${KEY_BACKUP}" ]]; then
            cp -a \
                "${KEY_BACKUP}" \
                "${CLIENT_KEYS}"
        fi

        systemctl start wazuh-agent || true

        die "Original Wazuh enrollment was restored."
    fi

    restore_auth_password_file

    info "Re-enrollment completed successfully."
}

###############################################################################
# Service Management
###############################################################################

start_agent() {
    info "Enabling and starting wazuh-agent..."

    systemctl daemon-reload

    systemctl enable wazuh-agent

    systemctl restart wazuh-agent

    if ! systemctl is-active \
        --quiet \
        wazuh-agent; then

        systemctl \
            --no-pager \
            --full \
            status wazuh-agent \
            || true

        die "wazuh-agent failed to start."
    fi

    info "wazuh-agent service is active."
}

###############################################################################
# Connection Validation
###############################################################################

verify_connection() {
    info "Waiting for agent connection to manager..."

    local attempt

    for attempt in {1..15}; do
        if ss -tnp 2>/dev/null \
            | grep -E "wazuh-agentd|:${COMM_PORT}" \
            | grep -q ":${COMM_PORT}"; then

            info "Established Wazuh communication session detected."
            return 0
        fi

        sleep 2
    done

    warn "No established TCP session detected after 30 seconds."

    if [[ -f "${OSSEC_DIR}/logs/ossec.log" ]]; then
        warn "Recent Wazuh agent log entries:"

        tail -n 30 \
            "${OSSEC_DIR}/logs/ossec.log" \
            >&2 || true
    fi

    return 1
}

###############################################################################
# Package Update Protection
###############################################################################

hold_agent_package() {
    [[ "${HOLD_PACKAGE}" == true ]] || return

    info "Placing wazuh-agent package on APT hold..."

    apt-mark hold wazuh-agent >/dev/null

    info "wazuh-agent package is now held."
}

###############################################################################
# Summary
###############################################################################

print_summary() {
    local installed_version

    installed_version="$(
        dpkg-query \
            -W \
            -f='${Version}' \
            wazuh-agent \
            2>/dev/null \
            || echo "unknown"
    )"

    cat <<EOF

============================================================
Wazuh Agent Onboarding Complete
============================================================

Manager:
  ${MANAGER}

Communication port:
  ${COMM_PORT}/TCP

Enrollment port:
  ${ENROLL_PORT}/TCP

Agent name:
  ${AGENT_NAME}

Agent group:
  ${AGENT_GROUP}

Installed package:
  ${installed_version}

Service:
  $(systemctl is-active wazuh-agent 2>/dev/null || echo unknown)

Package hold:
  ${HOLD_PACKAGE}

Agent log:
  ${OSSEC_DIR}/logs/ossec.log

Useful verification:

  sudo systemctl status wazuh-agent

  sudo tail -n 50 ${OSSEC_DIR}/logs/ossec.log

  sudo ss -tnp | grep ${COMM_PORT}

Manager-side verification:

  sudo /var/ossec/bin/agent_control -lc

Or use:

  Wazuh Dashboard
  → Agents management
  → Summary

============================================================

EOF
}

###############################################################################
# Secret Cleanup
###############################################################################

cleanup() {
    ENROLL_PASS=""

    # Ensure temporary password state is not left behind if the script exits
    # unexpectedly.
    if [[ -f "${AUTHD_PASS}" \
        && -n "${AUTHD_PASS_BACKUP}" ]]; then
        restore_auth_password_file || true
    fi
}

trap cleanup EXIT

###############################################################################
# Main
###############################################################################

main() {
    require_root
    parse_args "$@"
    validate_inputs
    validate_os

    get_enrollment_password

    install_dependencies
    preflight_connectivity

    detect_existing_agent

    if [[ "${AGENT_WAS_INSTALLED}" == true ]]; then
        reenroll_agent
    else
        install_wazuh_repository
        install_agent

        # If package installation did not produce an enrollment key,
        # explicitly enroll using agent-auth.
        if [[ ! -s "${CLIENT_KEYS}" ]]; then
            warn "No enrollment key detected after package installation."
            warn "Performing explicit enrollment."

            backup_existing_state
            prepare_auth_password_file

            args=(
                -m "${MANAGER}"
                -p "${ENROLL_PORT}"
                -A "${AGENT_NAME}"
            )

            if [[ -n "${AGENT_GROUP}" ]]; then
                args+=(
                    -G "${AGENT_GROUP}"
                )
            fi

            "${OSSEC_DIR}/bin/agent-auth" "${args[@]}"

            restore_auth_password_file
        fi
    fi

    start_agent

    if ! verify_connection; then
        die "Agent service is running but manager connectivity was not confirmed."
    fi

    hold_agent_package

    print_summary
}

main "$@"
