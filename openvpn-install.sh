#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034

# Secure OpenVPN server installer - Complete Version
# Based on https://github.com/angristan/openvpn-install

# Configuration constants
readonly DEFAULT_CERT_VALIDITY_DURATION_DAYS=3650
readonly DEFAULT_CRL_VALIDITY_DURATION_DAYS=5475
readonly EASYRSA_VERSION="3.2.5"
readonly EASYRSA_SHA256="662ee3b453155aeb1dff7096ec052cd83176c460cfa82ac130ef8568ec4df490"
readonly MAX_CLIENT_NAME_LENGTH=64

# =============================================================================
# Color Configuration
# =============================================================================
VERBOSE=${VERBOSE:-0}
LOG_FILE=${LOG_FILE:-openvpn-install.log}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-table}

if [[ -t 1 ]] && [[ "$TERM" != "dumb" ]] && [[ -z "$NO_COLOR" ]]; then
    readonly C_RESET='\033[0m'
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_YELLOW='\033[0;33m'
    readonly C_BLUE='\033[0;34m'
    readonly C_MAGENTA='\033[0;35m'
    readonly C_CYAN='\033[0;36m'
    readonly C_DIM='\033[0;90m'
    readonly C_BOLD='\033[1m'
else
    readonly C_RESET=''
    readonly C_RED=''
    readonly C_GREEN=''
    readonly C_YELLOW=''
    readonly C_BLUE=''
    readonly C_MAGENTA=''
    readonly C_CYAN=''
    readonly C_DIM=''
    readonly C_BOLD=''
fi

# =============================================================================
# DNS Providers Configuration (Expanded)
# =============================================================================

declare -A DNS_PROVIDERS
DNS_PROVIDERS=(
    # System & Local
    ["system"]="System default|System resolvers from /etc/resolv.conf"
    ["unbound"]="Unbound|Self-hosted recursive resolver"
    
    # Cloudflare
    ["cloudflare"]="Cloudflare Standard|1.1.1.1/1.0.0.1 - Privacy focused"
    ["cloudflare-malware"]="Cloudflare Malware|1.1.1.2/1.0.0.2 - Blocks malware"
    ["cloudflare-family"]="Cloudflare Family|1.1.1.3/1.0.0.3 - Blocks malware + adult"
    
    # Quad9
    ["quad9"]="Quad9 Standard|9.9.9.9/149.112.112.112 - Blocks malicious domains"
    ["quad9-uncensored"]="Quad9 Unfiltered|9.9.9.10/149.112.112.10 - No filtering"
    ["quad9-ecs"]="Quad9 with ECS|9.9.9.11/149.112.112.11 - With EDNS Client Subnet"
    
    # Google
    ["google"]="Google Standard|8.8.8.8/8.8.4.4 - Fast, global anycast"
    ["google-ipv6"]="Google IPv6|2001:4860:4860::8888/2001:4860:4860::8844"
    
    # OpenDNS
    ["opendns"]="OpenDNS Standard|208.67.222.222/208.67.220.220 - Cisco Umbrella"
    ["opendns-familyshield"]="OpenDNS FamilyShield|208.67.222.123/208.67.220.123 - Blocks adult content"
    
    # AdGuard
    ["adguard"]="AdGuard Standard|94.140.14.14/94.140.15.15 - Blocks ads & trackers"
    ["adguard-family"]="AdGuard Family|94.140.14.15/94.140.15.16 - Family protection"
    
    # NextDNS
    ["nextdns"]="NextDNS|45.90.28.0/45.90.30.0 - Customizable filtering"
    
    # Control D
    ["controld"]="Control D|76.76.2.0/76.76.10.0 - Free customizable DNS"
    ["controld-family"]="Control D Family|76.76.2.1/76.76.10.1 - Blocks malware + adult"
    
    # CleanBrowsing
    ["cleanbrowsing"]="CleanBrowsing Family|185.228.168.168/185.228.169.168 - Family filter"
    ["cleanbrowsing-adult"]="CleanBrowsing Adult|185.228.168.10/185.228.169.11 - Adult filter"
    ["cleanbrowsing-security"]="CleanBrowsing Security|185.228.168.9/185.228.169.9 - Malware blocking"
    
    # European Privacy
    ["fdn"]="FDN (France)|80.67.169.40/80.67.169.12 - French non-profit"
    ["dnswatch"]="DNS.WATCH (Germany)|84.200.69.80/84.200.70.40 - No logging"
    ["dns0"]="dns0.eu|193.110.81.0/185.253.5.0 - European privacy"
    ["dns0-family"]="dns0.eu Family|193.110.81.9/185.253.5.9 - Family protection"
    
    # Yandex
    ["yandex"]="Yandex Basic|77.88.8.8/77.88.8.1 - Russia"
    ["yandex-safe"]="Yandex Safe|77.88.8.88/77.88.8.2 - Blocks malware/phishing"
    ["yandex-family"]="Yandex Family|77.88.8.7/77.88.8.3 - Blocks adult content"
    
    # Security Focused
    ["comodo"]="Comodo Secure DNS|8.26.56.26/8.20.247.20 - Security focused"
    ["alternate"]="Alternate DNS|76.76.19.19/76.223.122.150 - No logging"
    ["norton"]="Norton ConnectSafe|199.85.126.10/199.85.127.10 - Security (deprecated)"
    
    # Neustar
    ["neustar"]="Neustar Standard|156.154.70.1/156.154.71.1 - Ultra-low latency"
    ["neustar-family"]="Neustar Family|156.154.70.2/156.154.71.2 - Blocks adult content"
    ["neustar-business"]="Neustar Business|156.154.70.3/156.154.71.3 - Blocks non-business"
    
    # Legacy/Other
    ["dyn"]="Dyn DNS|216.146.35.35/216.146.36.36 - Legacy Dyn"
    ["verisign"]="Verisign|64.6.64.6/64.6.65.6 - DNSSEC enabled"
    ["safe-surfer"]="Safe Surfer|104.236.10.9/104.131.144.4 - Open Source filter"
    
    # Custom
    ["custom"]="Custom|Manually enter DNS servers"
)

# =============================================================================
# Logging Functions
# =============================================================================

_log_to_file() {
    [[ -n "$LOG_FILE" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >>"$LOG_FILE"
}

_print_color() {
    local color="$1"
    local message="$2"
    [[ "$OUTPUT_FORMAT" != "json" ]] && echo -e "${color}${message}${C_RESET}"
}

print_header() {
    local text="$1"
    echo ""
    _print_color "${C_BOLD}${C_BLUE}" "════════════════════════════════════════════════════════"
    _print_color "${C_BOLD}${C_CYAN}" "  $text"
    _print_color "${C_BOLD}${C_BLUE}" "════════════════════════════════════════════════════════"
    echo ""
}

print_section() {
    echo ""
    _print_color "${C_BOLD}${C_YELLOW}" "▶ ${C_CYAN}$*"
    _print_color "${C_DIM}" "────────────────────────────────────────────────"
}

print_success() { _print_color "${C_GREEN}" "✓ $*"; _log_to_file "[SUCCESS] $*"; }
print_error() { _print_color "${C_RED}" "✗ $*" >&2; _log_to_file "[ERROR] $*"; }
print_warning() { _print_color "${C_YELLOW}" "⚠ $*"; _log_to_file "[WARNING] $*"; }
print_info() { _print_color "${C_BLUE}" "ℹ $*"; _log_to_file "[INFO] $*"; }
print_debug() { [[ $VERBOSE -eq 1 && $OUTPUT_FORMAT != "json" ]] && _print_color "${C_DIM}" "🔍 DEBUG: $*"; _log_to_file "[DEBUG] $*"; }
print_prompt() { [[ $NON_INTERACTIVE_INSTALL != "y" ]] && _print_color "${C_BOLD}${C_MAGENTA}" "? ${C_BOLD}$*"; }

print_menu_option() {
    local number="$1"
    local text="$2"
    local description="$3"
    echo -e "  ${C_BOLD}${C_YELLOW}[${number}]${C_RESET} ${C_CYAN}${text}${C_RESET}"
    [[ -n "$description" ]] && echo -e "     ${C_DIM}${description}${C_RESET}"
}

print_status() {
    local label="$1"
    local value="$2"
    local status_color="$C_GREEN"
    
    [[ "$value" == *"Not"* || "$value" == *"no"* || "$value" == *"disabled"* ]] && status_color="$C_RED"
    [[ "$value" == *"yes"* || "$value" == *"enabled"* ]] && status_color="$C_GREEN"
    
    printf "  ${C_DIM}%-20s${C_RESET} : ${status_color}%s${C_RESET}\n" "$label" "$value"
}

# Legacy functions for compatibility
log_info() { [[ $OUTPUT_FORMAT != "json" ]] && print_info "$*"; }
log_warn() { [[ $OUTPUT_FORMAT != "json" ]] && print_warning "$*"; }
log_error() { print_error "$*"; }
log_fatal() { print_error "$*"; _log_to_file "[FATAL] $*"; exit 1; }
log_success() { [[ $OUTPUT_FORMAT != "json" ]] && print_success "$*"; }
log_debug() { print_debug "$*"; }
log_prompt() { [[ $NON_INTERACTIVE_INSTALL != "y" ]] && print_prompt "$*"; }
log_header() { [[ $NON_INTERACTIVE_INSTALL != "y" ]] && print_header "$*"; }

# =============================================================================
# Helper Functions
# =============================================================================

run_cmd() {
    local desc="$1"
    shift
    print_debug "Running: $*"
    _log_to_file "[CMD] $*"
    
    if [[ $VERBOSE -eq 1 ]]; then
        "$@" 2>&1 | tee -a "$LOG_FILE"
    else
        "$@" >>"$LOG_FILE" 2>&1
    fi
    
    local ret=$?
    [[ $ret -eq 0 ]] && print_debug "$desc completed" || print_error "$desc failed"
    return $ret
}

run_cmd_fatal() {
    local desc="$1"
    shift
    run_cmd "$desc" "$@" || log_fatal "$desc failed"
}

get_dns_servers() {
    local provider="$1"
    local ipv4_only="$2"
    
    case "$provider" in
        # System & Local
        system|unbound|custom) echo "" ;;
        
        # Cloudflare
        cloudflare) echo "1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001" ;;
        cloudflare-malware) echo "1.1.1.2 1.0.0.2 2606:4700:4700::1112 2606:4700:4700::1002" ;;
        cloudflare-family) echo "1.1.1.3 1.0.0.3 2606:4700:4700::1113 2606:4700:4700::1003" ;;
        
        # Quad9
        quad9) echo "9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::9" ;;
        quad9-uncensored) echo "9.9.9.10 149.112.112.10 2620:fe::10 2620:fe::fe:10" ;;
        quad9-ecs) echo "9.9.9.11 149.112.112.11 2620:fe::11 2620:fe::fe:11" ;;
        
        # Google
        google) echo "8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844" ;;
        google-ipv6) echo "2001:4860:4860::8888 2001:4860:4860::8844" ;;
        
        # OpenDNS
        opendns) echo "208.67.222.222 208.67.220.220 2620:119:35::35 2620:119:53::53" ;;
        opendns-familyshield) echo "208.67.222.123 208.67.220.123 2620:119:35::123 2620:119:53::123" ;;
        
        # AdGuard
        adguard) echo "94.140.14.14 94.140.15.15 2a10:50c0::ad1:ff 2a10:50c0::ad2:ff" ;;
        adguard-family) echo "94.140.14.15 94.140.15.16 2a10:50c0::bad1:ff 2a10:50c0::bad2:ff" ;;
        
        # NextDNS
        nextdns) echo "45.90.28.0 45.90.30.0 2a07:a8c0:: 2a07:a8c1::" ;;
        
        # Control D
        controld) echo "76.76.2.0 76.76.10.0 2606:1a40:: 2606:1a40:1::" ;;
        controld-family) echo "76.76.2.1 76.76.10.1 2606:1a40::1 2606:1a40:1::1" ;;
        
        # CleanBrowsing
        cleanbrowsing) echo "185.228.168.168 185.228.169.168 2a0d:2a00:1:: 2a0d:2a00:2::" ;;
        cleanbrowsing-adult) echo "185.228.168.10 185.228.169.11 2a0d:2a00:1::2 2a0d:2a00:2::2" ;;
        cleanbrowsing-security) echo "185.228.168.9 185.228.169.9 2a0d:2a00:1::1 2a0d:2a00:2::1" ;;
        
        # European
        fdn) echo "80.67.169.40 80.67.169.12 2001:910:800::40 2001:910:800::12" ;;
        dnswatch) echo "84.200.69.80 84.200.70.40 2001:1608:10:25::1c04:b12f 2001:1608:10:25::9249:d69b" ;;
        dns0) echo "193.110.81.0 185.253.5.0 2a0f:fc80:: 2a0f:fc81::" ;;
        dns0-family) echo "193.110.81.9 185.253.5.9 2a0f:fc80::9 2a0f:fc81::9" ;;
        
        # Yandex
        yandex) echo "77.88.8.8 77.88.8.1 2a02:6b8::feed:0ff 2a02:6b8:0:1::feed:0ff" ;;
        yandex-safe) echo "77.88.8.88 77.88.8.2 2a02:6b8::feed:bad 2a02:6b8:0:1::feed:bad" ;;
        yandex-family) echo "77.88.8.7 77.88.8.3 2a02:6b8::feed:a11 2a02:6b8:0:1::feed:a11" ;;
        
        # Security
        comodo) echo "8.26.56.26 8.20.247.20" ;;
        alternate) echo "76.76.19.19 76.223.122.150" ;;
        norton) echo "199.85.126.10 199.85.127.10" ;;
        
        # Neustar
        neustar) echo "156.154.70.1 156.154.71.1 2610:a1:1018::1 2610:a1:1019::1" ;;
        neustar-family) echo "156.154.70.2 156.154.71.2 2610:a1:1018::2 2610:a1:1019::2" ;;
        neustar-business) echo "156.154.70.3 156.154.71.3 2610:a1:1018::3 2610:a1:1019::3" ;;
        
        # Legacy
        dyn) echo "216.146.35.35 216.146.36.36" ;;
        verisign) echo "64.6.64.6 64.6.65.6" ;;
        safe-surfer) echo "104.236.10.9 104.131.144.4" ;;
    esac | if [[ "$ipv4_only" == "true" ]]; then
        grep -v ':'
    else
        cat
    fi
}

# =============================================================================
# Validation Functions
# =============================================================================

validate_port() { [[ "$1" =~ ^[0-9]+$ && $1 -ge 1 && $1 -le 65535 ]]; }
validate_mtu() { [[ "$1" =~ ^[0-9]+$ && $1 -ge 576 && $1 -le 65535 ]]; }
validate_positive_int() { [[ "$1" =~ ^[0-9]+$ && $1 -ge 1 ]]; }
is_valid_client_name() { [[ "$1" =~ ^[a-zA-Z0-9_-]+$ && ${#1} -le $MAX_CLIENT_NAME_LENGTH ]]; }

validate_client_name() {
    local name="$1"
    [[ -z "$name" ]] && log_fatal "Client name cannot be empty"
    is_valid_client_name "$name" || log_fatal "Invalid client name: $name"
}

# =============================================================================
# System Check Functions
# =============================================================================

isRoot() { [ "$EUID" -eq 0 ]; }
tunAvailable() { [ -e /dev/net/tun ]; }

checkOS() {
    if [[ -e /etc/debian_version ]]; then
        OS="debian"
        source /etc/os-release
        [[ $ID == "ubuntu" ]] && OS="ubuntu"
    elif [[ -e /etc/os-release ]]; then
        source /etc/os-release
        [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]] && OS="centos"
        [[ $ID == "fedora" ]] && OS="fedora"
        [[ $ID == "arch" ]] && OS="arch"
    else
        log_fatal "Unsupported OS"
    fi
}

initialCheck() {
    isRoot || log_fatal "Must run as root"
    tunAvailable || log_fatal "TUN not available"
    checkOS
}

# =============================================================================
# OpenVPN Status Functions
# =============================================================================

isOpenVPNInstalled() {
    [[ -e /etc/openvpn/server/server.conf ]]
}

requireOpenVPN() {
    if ! isOpenVPNInstalled; then
        log_fatal "OpenVPN is not installed. Run '$SCRIPT_NAME install' first."
    fi
}

requireNoOpenVPN() {
    if isOpenVPNInstalled; then
        log_fatal "OpenVPN is already installed. Use '$SCRIPT_NAME client' to manage clients or '$SCRIPT_NAME uninstall' to remove."
    fi
}

# =============================================================================
# IP Detection Functions
# =============================================================================

resolvePublicIPv4() {
    curl -f -m 5 -sS --retry 2 -4 https://api.seeip.org 2>/dev/null ||
    curl -f -m 5 -sS --retry 2 -4 https://ifconfig.me 2>/dev/null ||
    curl -f -m 5 -sS --retry 2 -4 https://api.ipify.org 2>/dev/null
}

resolvePublicIPv6() {
    curl -f -m 5 -sS --retry 2 -6 https://api6.seeip.org 2>/dev/null ||
    curl -f -m 5 -sS --retry 2 -6 https://ifconfig.me 2>/dev/null
}

detect_server_ips() {
    IP_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    IP_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    IP=$([[ $ENDPOINT_TYPE == "6" ]] && echo "$IP_IPV6" || echo "$IP_IPV4")
}

prepare_network_config() {
    VPN_GATEWAY_IPV4="${VPN_SUBNET_IPV4%.*}.1"
    [[ $CLIENT_IPV6 == "y" ]] && VPN_GATEWAY_IPV6="${VPN_SUBNET_IPV6}1"
    IPV6_SUPPORT="$CLIENT_IPV6"
}

# =============================================================================
# DNS Provider Selection (Expanded)
# =============================================================================

select_dns_provider() {
    print_section "DNS Provider Selection"
    echo ""
    
    local categories=(
        "System & Local"
        "Cloudflare"
        "Quad9"
        "Google"
        "OpenDNS"
        "AdGuard"
        "NextDNS/Control D"
        "CleanBrowsing"
        "European Privacy"
        "Yandex"
        "Security Focused"
        "Neustar"
        "Legacy/Other"
        "Custom"
    )
    
    local providers=(
        "system,unbound"
        "cloudflare,cloudflare-malware,cloudflare-family"
        "quad9,quad9-uncensored,quad9-ecs"
        "google,google-ipv6"
        "opendns,opendns-familyshield"
        "adguard,adguard-family"
        "nextdns,controld,controld-family"
        "cleanbrowsing,cleanbrowsing-adult,cleanbrowsing-security"
        "fdn,dnswatch,dns0,dns0-family"
        "yandex,yandex-safe,yandex-family"
        "comodo,alternate,norton"
        "neustar,neustar-family,neustar-business"
        "dyn,verisign,safe-surfer"
        "custom"
    )
    
    local current=0
    local selected=""
    
    while [[ -z "$selected" ]]; do
        echo -e "${C_BOLD}${C_YELLOW}Category: ${categories[$current]}${C_RESET}"
        echo -e "${C_DIM}────────────────────────${C_RESET}"
        
        IFS=',' read -ra provs <<< "${providers[$current]}"
        local i=1
        for p in "${provs[@]}"; do
            if [[ -n "${DNS_PROVIDERS[$p]}" ]]; then
                IFS='|' read -r name desc <<< "${DNS_PROVIDERS[$p]}"
                printf "  ${C_GREEN}%2d)${C_RESET} ${C_CYAN}%-20s${C_RESET} ${C_DIM}%s${C_RESET}\n" "$i" "$name" "$desc"
                ((i++))
            fi
        done
        
        echo ""
        printf "  ${C_YELLOW}n)${C_RESET} Next  ${C_YELLOW}p)${C_RESET} Prev  ${C_YELLOW}q)${C_RESET} Quit"
        echo ""
        
        read -rp "$(print_prompt "Select [1-$(($i-1)) or n/p/q]: ")" choice
        
        case "$choice" in
            [0-9]*)
                if [[ $choice -ge 1 && $choice -le $(($i-1)) ]]; then
                    selected="${provs[$((choice-1))]}"
                else
                    print_warning "Invalid selection"
                fi
                ;;
            n|N) ((current = (current + 1) % ${#categories[@]})) ;;
            p|P) ((current = (current - 1 + ${#categories[@]}) % ${#categories[@]})) ;;
            q|Q) return 1 ;;
            *) print_warning "Invalid selection" ;;
        esac
        echo ""
    done
    
    DNS="$selected"
    print_success "Selected: ${DNS_PROVIDERS[$DNS]%%|*}"
}

# =============================================================================
# Installation Questions
# =============================================================================

set_installation_defaults() {
    ENDPOINT_TYPE="${ENDPOINT_TYPE:-4}"
    CLIENT_IPV4="${CLIENT_IPV4:-y}"
    CLIENT_IPV6="${CLIENT_IPV6:-n}"
    VPN_SUBNET_IPV4="${VPN_SUBNET_IPV4:-10.8.0.0}"
    VPN_SUBNET_IPV6="${VPN_SUBNET_IPV6:-fd42:42:42:42::}"
    PORT="${PORT:-1194}"
    PROTOCOL="${PROTOCOL:-udp}"
    DNS="${DNS:-cloudflare}"
    MULTI_CLIENT="${MULTI_CLIENT:-n}"
    MTU="${MTU:-1500}"
    
    # Encryption defaults
    CIPHER="${CIPHER:-AES-128-GCM}"
    CERT_TYPE="${CERT_TYPE:-ecdsa}"
    CERT_CURVE="${CERT_CURVE:-prime256v1}"
    RSA_KEY_SIZE="${RSA_KEY_SIZE:-2048}"
    TLS_VERSION_MIN="${TLS_VERSION_MIN:-1.2}"
    TLS13_CIPHERSUITES="${TLS13_CIPHERSUITES:-TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256}"
    TLS_GROUPS="${TLS_GROUPS:-X25519:prime256v1:secp384r1:secp521r1}"
    HMAC_ALG="${HMAC_ALG:-SHA256}"
    TLS_SIG="${TLS_SIG:-crypt-v2}"
    AUTH_MODE="${AUTH_MODE:-pki}"
    
    # Derive CC_CIPHER if not set
    if [[ -z $CC_CIPHER ]]; then
        if [[ $CERT_TYPE == "ecdsa" ]]; then
            CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
        else
            CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
        fi
    fi
    
    # Client
    CLIENT="${CLIENT:-client}"
    PASS="${PASS:-1}"
    CLIENT_CERT_DURATION_DAYS="${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}"
    SERVER_CERT_DURATION_DAYS="${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}"
}

validate_configuration() {
    [[ $PROTOCOL =~ ^(udp|tcp)$ ]] || log_fatal "Invalid protocol: $PROTOCOL"
    [[ -n "${DNS_PROVIDERS[$DNS]}" || $DNS == "custom" ]] || log_fatal "Invalid DNS provider: $DNS"
    [[ $CERT_TYPE =~ ^(ecdsa|rsa)$ ]] || log_fatal "Invalid cert type: $CERT_TYPE"
    [[ $TLS_SIG =~ ^(crypt-v2|crypt|auth)$ ]] || log_fatal "Invalid TLS mode: $TLS_SIG"
    [[ $AUTH_MODE =~ ^(pki|fingerprint)$ ]] || log_fatal "Invalid auth mode: $AUTH_MODE"
    validate_port "$PORT" || log_fatal "Invalid port: $PORT"
    [[ $CLIENT_IPV4 == "y" || $CLIENT_IPV6 == "y" ]] || log_fatal "At least one IP version required"
    [[ $ENDPOINT_TYPE =~ ^[46]$ ]] || log_fatal "Invalid endpoint type: $ENDPOINT_TYPE"
}

installQuestions() {
    print_header "OpenVPN Installer"
    echo ""
    
    IP_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    IP_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    
    echo ""
    print_prompt "What IP version should clients use to connect?"
    
    if [[ -n $IP_IPV4 ]]; then
        echo "  1) IPv4"
        [[ -n $IP_IPV6 ]] && echo "  2) IPv6"
        DEFAULT=1
    else
        echo "  1) IPv6"
        DEFAULT=1
    fi
    
    read -rp "$(print_prompt "Select [1]: ")" -e -i $DEFAULT ENDPOINT_TYPE_CHOICE
    ENDPOINT_TYPE=$([[ $ENDPOINT_TYPE_CHOICE == "2" ]] && echo "6" || echo "4")
    IP=$([[ $ENDPOINT_TYPE == "6" ]] && echo "$IP_IPV6" || echo "$IP_IPV4")
    
    if [[ $ENDPOINT_TYPE == "4" && $IP =~ ^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168) ]]; then
        echo ""
        print_warning "Server appears to be behind NAT"
        DEFAULT_ENDPOINT=$(resolvePublicIPv4)
        read -rp "Public IPv4/hostname: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
    fi
    
    echo ""
    print_prompt "What IP versions should VPN clients use?"
    echo "  1) IPv4 only"
    echo "  2) IPv6 only"
    echo "  3) Dual-stack"
    read -rp "$(print_prompt "Select [1]: ")" -e -i 1 CLIENT_IP_CHOICE
    
    case $CLIENT_IP_CHOICE in
        2) CLIENT_IPV4="n"; CLIENT_IPV6="y" ;;
        3) CLIENT_IPV4="y"; CLIENT_IPV6="y" ;;
        *) CLIENT_IPV4="y"; CLIENT_IPV6="n" ;;
    esac
    
    if [[ $CLIENT_IPV4 == "y" ]]; then
        echo ""
        print_prompt "IPv4 VPN subnet:"
        echo "  1) Default: 10.8.0.0/24"
        echo "  2) Custom"
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 SUBNET_IPV4_CHOICE
        
        if [[ $SUBNET_IPV4_CHOICE == "2" ]]; then
            until [[ $VPN_SUBNET_IPV4 =~ ^10\.[0-9]+\.[0-9]+\.0$ ]]; do
                read -rp "Custom subnet (e.g., 10.9.0.0): " VPN_SUBNET_IPV4
            done
        else
            VPN_SUBNET_IPV4="10.8.0.0"
        fi
    else
        VPN_SUBNET_IPV4="10.8.0.0"
    fi
    
    if [[ $CLIENT_IPV6 == "y" ]]; then
        echo ""
        print_prompt "IPv6 VPN subnet:"
        echo "  1) Default: fd42:42:42:42::/112"
        echo "  2) Custom"
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 SUBNET_IPV6_CHOICE
        
        if [[ $SUBNET_IPV6_CHOICE == "2" ]]; then
            until [[ $VPN_SUBNET_IPV6 =~ ^fd[0-9a-f:]+::$ ]]; do
                read -rp "Custom subnet (e.g., fd12:3456:789a::): " VPN_SUBNET_IPV6
            done
        else
            VPN_SUBNET_IPV6="fd42:42:42:42::"
        fi
    fi
    
    echo ""
    print_prompt "What port should OpenVPN listen on?"
    echo "  1) Default: 1194"
    echo "  2) Custom"
    echo "  3) Random [49152-65535]"
    read -rp "$(print_prompt "Select [1]: ")" -e -i 1 PORT_CHOICE
    
    case $PORT_CHOICE in
        2)
            until validate_port "$PORT"; do
                read -rp "Custom port [1-65535]: " -e -i 1194 PORT
            done
            ;;
        3) PORT=$(shuf -i 49152-65535 -n1) ;;
        *) PORT="1194" ;;
    esac
    
    echo ""
    print_prompt "What protocol should OpenVPN use?"
    echo "  1) UDP (recommended)"
    echo "  2) TCP"
    read -rp "$(print_prompt "Select [1]: ")" -e -i 1 PROTOCOL_CHOICE
    PROTOCOL=$([[ $PROTOCOL_CHOICE == "2" ]] && echo "tcp" || echo "udp")
    
    echo ""
    select_dns_provider || log_fatal "DNS selection cancelled"
    
    echo ""
    print_prompt "Allow multiple devices per client?"
    read -rp "$(print_prompt "Allow? [y/N]: ")" -e -i n MULTI_CLIENT
    
    echo ""
    print_prompt "Customize tunnel MTU?"
    echo "  1) Default (1500)"
    echo "  2) Custom"
    read -rp "$(print_prompt "Select [1]: ")" -e -i 1 MTU_CHOICE
    
    if [[ $MTU_CHOICE == "2" ]]; then
        until validate_mtu "$MTU"; do
            read -rp "MTU [576-65535]: " -e -i 1500 MTU
        done
    fi
    
    echo ""
    print_prompt "Choose authentication mode:"
    echo "  1) PKI (Certificate Authority) - Traditional"
    echo "  2) Peer Fingerprint (OpenVPN 2.6+) - Simpler"
    read -rp "$(print_prompt "Select [1]: ")" -e -i 1 AUTH_MODE_CHOICE
    AUTH_MODE=$([[ $AUTH_MODE_CHOICE == "2" ]] && echo "fingerprint" || echo "pki")
    
    # =========================================================================
    # Encryption Settings - Complete Customization
    # =========================================================================
    
    echo ""
    print_prompt "Customize encryption settings?"
    read -rp "$(print_prompt "Customize? [y/N]: ")" -e -i n CUSTOMIZE_ENC
    
    if [[ $CUSTOMIZE_ENC == "y" ]]; then
        # Cipher selection
        echo ""
        print_section "Cipher Selection"
        print_prompt "Choose data channel cipher:"
        echo "  1) AES-128-GCM (recommended, fast)"
        echo "  2) AES-256-GCM (more secure, slightly slower)"
        echo "  3) CHACHA20-POLY1305 (good for devices without AES-NI)"
        echo "  4) AES-128-CBC (legacy)"
        echo "  5) AES-256-CBC (legacy)"
        
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 CIPHER_CHOICE
        case $CIPHER_CHOICE in
            2) CIPHER="AES-256-GCM" ;;
            3) CIPHER="CHACHA20-POLY1305" ;;
            4) CIPHER="AES-128-CBC" ;;
            5) CIPHER="AES-256-CBC" ;;
            *) CIPHER="AES-128-GCM" ;;
        esac
        
        # Certificate type
        echo ""
        print_section "Certificate Type"
        print_prompt "Choose certificate key type:"
        echo "  1) ECDSA (recommended, smaller keys, faster)"
        echo "  2) RSA (traditional, wider compatibility)"
        
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 CERT_TYPE_CHOICE
        
        if [[ $CERT_TYPE_CHOICE == "2" ]]; then
            CERT_TYPE="rsa"
            echo ""
            print_prompt "Choose RSA key size:"
            echo "  1) 2048 bits (default, good security)"
            echo "  2) 3072 bits (stronger)"
            echo "  3) 4096 bits (strongest, slower)"
            
            read -rp "$(print_prompt "Select [1]: ")" -e -i 1 RSA_SIZE_CHOICE
            case $RSA_SIZE_CHOICE in
                2) RSA_KEY_SIZE="3072" ;;
                3) RSA_KEY_SIZE="4096" ;;
                *) RSA_KEY_SIZE="2048" ;;
            esac
        else
            CERT_TYPE="ecdsa"
            echo ""
            print_prompt "Choose ECDSA curve:"
            echo "  1) prime256v1 (default, good security)"
            echo "  2) secp384r1 (stronger)"
            echo "  3) secp521r1 (strongest)"
            
            read -rp "$(print_prompt "Select [1]: ")" -e -i 1 CURVE_CHOICE
            case $CURVE_CHOICE in
                2) CERT_CURVE="secp384r1" ;;
                3) CERT_CURVE="secp521r1" ;;
                *) CERT_CURVE="prime256v1" ;;
            esac
        fi
        
        # Control channel cipher
        echo ""
        print_section "Control Channel"
        print_prompt "Choose control channel cipher:"
        
        if [[ $CERT_TYPE == "ecdsa" ]]; then
            echo "  1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
            echo "  2) ECDHE-ECDSA-AES-256-GCM-SHA384"
            echo "  3) ECDHE-ECDSA-CHACHA20-POLY1305"
            
            read -rp "$(print_prompt "Select [1]: ")" -e -i 1 CC_CHOICE
            case $CC_CHOICE in
                2) CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384" ;;
                3) CC_CIPHER="TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256" ;;
                *) CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256" ;;
            esac
        else
            echo "  1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
            echo "  2) ECDHE-RSA-AES-256-GCM-SHA384"
            echo "  3) ECDHE-RSA-CHACHA20-POLY1305"
            
            read -rp "$(print_prompt "Select [1]: ")" -e -i 1 CC_CHOICE
            case $CC_CHOICE in
                2) CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384" ;;
                3) CC_CIPHER="TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256" ;;
                *) CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256" ;;
            esac
        fi
        
        # TLS version
        echo ""
        print_prompt "Choose minimum TLS version:"
        echo "  1) TLS 1.2 (recommended, compatible)"
        echo "  2) TLS 1.3 (more secure, requires OpenVPN 2.5+)"
        
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 TLS_VER_CHOICE
        TLS_VERSION_MIN=$([[ $TLS_VER_CHOICE == "2" ]] && echo "1.3" || echo "1.2")
        
        # TLS 1.3 ciphers
        echo ""
        print_prompt "Choose TLS 1.3 cipher suites:"
        echo "  1) All secure ciphers (recommended)"
        echo "  2) AES-256-GCM only"
        echo "  3) AES-128-GCM only"
        echo "  4) ChaCha20-Poly1305 only"
        
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 TLS13_CHOICE
        case $TLS13_CHOICE in
            2) TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384" ;;
            3) TLS13_CIPHERSUITES="TLS_AES_128_GCM_SHA256" ;;
            4) TLS13_CIPHERSUITES="TLS_CHACHA20_POLY1305_SHA256" ;;
            *) TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256" ;;
        esac
        
        # TLS groups
        echo ""
        print_prompt "Choose TLS key exchange groups:"
        echo "  1) All modern curves (recommended)"
        echo "  2) X25519 only (most secure)"
        echo "  3) NIST curves only (prime256v1, secp384r1, secp521r1)"
        
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 TLS_GROUPS_CHOICE
        case $TLS_GROUPS_CHOICE in
            2) TLS_GROUPS="X25519" ;;
            3) TLS_GROUPS="prime256v1:secp384r1:secp521r1" ;;
            *) TLS_GROUPS="X25519:prime256v1:secp384r1:secp521r1" ;;
        esac
        
        # HMAC algorithm
        echo ""
        print_prompt "Choose HMAC digest algorithm:"
        echo "  1) SHA256 (recommended)"
        echo "  2) SHA384"
        echo "  3) SHA512"
        
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 HMAC_CHOICE
        case $HMAC_CHOICE in
            2) HMAC_ALG="SHA384" ;;
            3) HMAC_ALG="SHA512" ;;
            *) HMAC_ALG="SHA256" ;;
        esac
        
        # TLS signature mode
        echo ""
        print_prompt "Choose control channel security:"
        echo "  1) tls-crypt-v2 (recommended) - Encrypts control channel, unique key per client"
        echo "  2) tls-crypt - Encrypts control channel, shared key"
        echo "  3) tls-auth - Authenticates only, no encryption"
        
        read -rp "$(print_prompt "Select [1]: ")" -e -i 1 TLS_SIG_CHOICE
        case $TLS_SIG_CHOICE in
            2) TLS_SIG="crypt" ;;
            3) TLS_SIG="auth" ;;
            *) TLS_SIG="crypt-v2" ;;
        esac
        
    else
        # Default encryption settings
        CIPHER="AES-128-GCM"
        CERT_TYPE="ecdsa"
        CERT_CURVE="prime256v1"
        RSA_KEY_SIZE="2048"
        CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
        TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
        TLS_VERSION_MIN="1.2"
        TLS_GROUPS="X25519:prime256v1:secp384r1:secp521r1"
        HMAC_ALG="SHA256"
        TLS_SIG="crypt-v2"
    fi
    
    echo ""
    print_section "Configuration Summary"
    print_status "Protocol" "$PROTOCOL"
    print_status "Port" "$PORT"
    print_status "DNS" "${DNS_PROVIDERS[$DNS]%%|*}"
    print_status "Auth Mode" "$AUTH_MODE"
    print_status "Cipher" "$CIPHER"
    print_status "Certificate Type" "$CERT_TYPE"
    echo ""
    
    read -n1 -r -p "$(print_prompt "Press any key to continue...")"
    echo ""
}

# =============================================================================
# Installation Functions
# =============================================================================

installOpenVPNRepo() {
    log_info "Setting up OpenVPN repository..."
    
    if [[ $OS =~ (debian|ubuntu) ]]; then
        apt-get update
        apt-get install -y ca-certificates curl
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg -o /etc/apt/keyrings/openvpn-repo-public.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/openvpn-repo-public.asc] https://build.openvpn.net/debian/openvpn/stable ${VERSION_CODENAME} main" >/etc/apt/sources.list.d/openvpn-aptrepo.list
        apt-get update
    fi
}

installUnbound() {
    log_info "Installing Unbound..."
    
    if [[ ! -e /etc/unbound/unbound.conf ]]; then
        case $OS in
            debian|ubuntu) apt-get install -y unbound ;;
            centos|oracle) yum install -y unbound ;;
            fedora|amzn2023) dnf install -y unbound ;;
            arch) pacman -Syu --noconfirm unbound ;;
        esac
    fi
    
    mkdir -p /etc/unbound/unbound.conf.d
    VPN_GATEWAY_IPV4="${VPN_SUBNET_IPV4%.*}.1"
    [[ $CLIENT_IPV6 == "y" ]] && VPN_GATEWAY_IPV6="${VPN_SUBNET_IPV6}1"
    
    cat > /etc/unbound/unbound.conf.d/openvpn.conf <<EOF
server:
    interface: $VPN_GATEWAY_IPV4
    access-control: $VPN_SUBNET_IPV4/24 allow
    hide-identity: yes
    hide-version: yes
    prefetch: yes
EOF
    
    systemctl enable unbound
    systemctl restart unbound
}

installOpenVPN() {
    print_header "Installing OpenVPN"
    
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    [[ -z $NIC && $CLIENT_IPV6 == "y" ]] && NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
    
    installOpenVPNRepo
    
    log_info "Installing OpenVPN packages..."
    case $OS in
        debian|ubuntu) apt-get install -y openvpn iptables openssl ca-certificates curl tar bind9-host socat ;;
        centos|oracle) yum install -y epel-release openvpn iptables openssl ca-certificates curl tar bind-utils socat ;;
        fedora|amzn2023) dnf install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat ;;
        arch) pacman -Syu --needed --noconfirm openvpn iptables openssl ca-certificates curl tar bind socat ;;
    esac
    
    if id openvpn &>/dev/null; then
        OPENVPN_USER=openvpn
        OPENVPN_GROUP=$(id -gn openvpn)
    else
        OPENVPN_USER=nobody
        OPENVPN_GROUP=$(grep -qs "^nogroup:" /etc/group && echo "nogroup" || echo "nobody")
    fi
    
    if [[ ! -d /etc/openvpn/server/easy-rsa/ ]]; then
        mkdir -p /etc/openvpn/server/easy-rsa
        curl -fL -o /tmp/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz
        tar xzf /tmp/easy-rsa.tgz --strip-components=1 -C /etc/openvpn/server/easy-rsa
        rm -f /tmp/easy-rsa.tgz
        
        cd /etc/openvpn/server/easy-rsa || exit
        
        cat > vars <<EOF
set_var EASYRSA_ALGO $([[ $CERT_TYPE == "ecdsa" ]] && echo "ec" || echo "rsa")
set_var EASYRSA_CURVE $CERT_CURVE
set_var EASYRSA_KEY_SIZE ${RSA_KEY_SIZE:-2048}
EOF
        
        SERVER_CN="cn_$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 16 | head -n1)"
        SERVER_NAME="server_$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 16 | head -n1)"
        
        ./easyrsa init-pki
        
        if [[ $AUTH_MODE == "pki" ]]; then
            export EASYRSA_CA_EXPIRE=$DEFAULT_CERT_VALIDITY_DURATION_DAYS
            ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass
            
            export EASYRSA_CERT_EXPIRE=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
            ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
            
            export EASYRSA_CRL_DAYS=$DEFAULT_CRL_VALIDITY_DURATION_DAYS
            ./easyrsa gen-crl
        else
            export EASYRSA_CERT_EXPIRE=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
            ./easyrsa --batch self-sign-server "$SERVER_NAME" nopass
        fi
        
        case $TLS_SIG in
            crypt-v2) openvpn --genkey tls-crypt-v2-server /etc/openvpn/server/tls-crypt-v2.key ;;
            crypt) openvpn --genkey secret /etc/openvpn/server/tls-crypt.key ;;
            auth) openvpn --genkey secret /etc/openvpn/server/tls-auth.key ;;
        esac
        
        echo "$SERVER_NAME" > SERVER_NAME_GENERATED
        echo "$AUTH_MODE" > AUTH_MODE_GENERATED
    else
        cd /etc/openvpn/server/easy-rsa || exit
        SERVER_NAME=$(cat SERVER_NAME_GENERATED 2>/dev/null || echo "server")
        AUTH_MODE=$(cat AUTH_MODE_GENERATED 2>/dev/null || echo "pki")
    fi
    
    if [[ $AUTH_MODE == "pki" ]]; then
        cp pki/ca.crt pki/private/ca.key pki/issued/$SERVER_NAME.crt pki/private/$SERVER_NAME.key pki/crl.pem /etc/openvpn/server/ 2>/dev/null
    else
        cp pki/issued/$SERVER_NAME.crt pki/private/$SERVER_NAME.key /etc/openvpn/server/ 2>/dev/null
    fi
    
    cat > /etc/openvpn/server/server.conf <<EOF
port $PORT
proto ${PROTOCOL}${ENDPOINT_TYPE}
dev tun
user $OPENVPN_USER
group $OPENVPN_GROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server $VPN_SUBNET_IPV4 255.255.255.0
EOF
    
    [[ $CLIENT_IPV6 == "y" ]] && echo "server-ipv6 ${VPN_SUBNET_IPV6}/112" >> /etc/openvpn/server/server.conf
    [[ $MULTI_CLIENT == "y" ]] && echo "duplicate-cn" >> /etc/openvpn/server/server.conf
    [[ $MULTI_CLIENT != "y" ]] && echo "ifconfig-pool-persist ipp.txt" >> /etc/openvpn/server/server.conf
    
    if [[ $DNS == "system" ]]; then
        RESOLVCONF=$(grep -q "127.0.0.53" /etc/resolv.conf && echo "/run/systemd/resolve/resolv.conf" || echo "/etc/resolv.conf")
        grep nameserver "$RESOLVCONF" | while read -r line; do
            dns=$(echo "$line" | awk '{print $2}')
            echo "push \"dhcp-option DNS $dns\"" >> /etc/openvpn/server/server.conf
        done
    elif [[ $DNS == "unbound" ]]; then
        VPN_GATEWAY_IPV4="${VPN_SUBNET_IPV4%.*}.1"
        [[ $CLIENT_IPV4 == "y" ]] && echo "push \"dhcp-option DNS $VPN_GATEWAY_IPV4\"" >> /etc/openvpn/server/server.conf
        [[ $CLIENT_IPV6 == "y" ]] && echo "push \"dhcp-option DNS $VPN_GATEWAY_IPV6\"" >> /etc/openvpn/server/server.conf
    elif [[ $DNS != "custom" ]]; then
        while read -r dns; do
            [[ -n $dns ]] && echo "push \"dhcp-option DNS $dns\"" >> /etc/openvpn/server/server.conf
        done < <(get_dns_servers "$DNS" "false")
    fi
    
    echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    [[ $CLIENT_IPV6 == "y" ]] && echo 'push "redirect-gateway ipv6"' >> /etc/openvpn/server/server.conf
    
    {
        echo "dh none"
        echo "tls-groups $TLS_GROUPS"
        [[ $TLS_SIG == "crypt-v2" ]] && echo "tls-crypt-v2 tls-crypt-v2.key"
        [[ $TLS_SIG == "crypt" ]] && echo "tls-crypt tls-crypt.key"
        [[ $TLS_SIG == "auth" ]] && echo "tls-auth tls-auth.key 0"
        [[ $AUTH_MODE == "pki" ]] && echo "crl-verify crl.pem"
        [[ $AUTH_MODE == "pki" ]] && echo "ca ca.crt"
        echo "cert $SERVER_NAME.crt"
        echo "key $SERVER_NAME.key"
        echo "auth $HMAC_ALG"
        echo "cipher $CIPHER"
        echo "data-ciphers $CIPHER"
        echo "tls-server"
        echo "tls-version-min $TLS_VERSION_MIN"
        [[ $AUTH_MODE == "pki" ]] && echo "remote-cert-tls client"
        echo "tls-cipher $CC_CIPHER"
        echo "tls-ciphersuites $TLS13_CIPHERSUITES"
        echo "client-config-dir ccd"
        echo "status /var/log/openvpn/status.log"
        echo "verb 3"
    } >> /etc/openvpn/server/server.conf
    
    mkdir -p /etc/openvpn/server/ccd /var/log/openvpn
    
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn.conf
    [[ $CLIENT_IPV6 == "y" ]] && echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.d/99-openvpn.conf
    sysctl --system
    
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="$PORT/$PROTOCOL"
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --reload
    else
        iptables -t nat -A POSTROUTING -s $VPN_SUBNET_IPV4/24 -o $NIC -j MASQUERADE 2>/dev/null
        iptables -A INPUT -i tun+ -j ACCEPT 2>/dev/null
        iptables -A FORWARD -i tun+ -j ACCEPT 2>/dev/null
        iptables -A FORWARD -o tun+ -j ACCEPT 2>/dev/null
        iptables -A INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT 2>/dev/null
    fi
    
    systemctl daemon-reload
    systemctl enable openvpn-server@server
    [[ $AUTH_MODE == "pki" ]] && systemctl restart openvpn-server@server
    
    [[ $DNS == "unbound" ]] && installUnbound
    
    cat > /etc/openvpn/server/client-template.txt <<EOF
client
dev tun
proto $PROTOCOL
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth $HMAC_ALG
cipher $CIPHER
data-ciphers $CIPHER
verb 3
EOF
    
    if [[ $NEW_CLIENT != "n" ]]; then
        print_info "Generating first client..."
        newClient
        [[ $AUTH_MODE == "fingerprint" ]] && systemctl restart openvpn-server@server
    fi
    
    print_success "OpenVPN installation complete!"
}

# =============================================================================
# Client Management Functions
# =============================================================================

getHomeDir() {
    local client="$1"
    if [[ -d "/home/${client}" ]]; then
        echo "/home/${client}"
    elif [[ -n "$SUDO_USER" ]] && [[ "$SUDO_USER" != "root" ]]; then
        echo "/home/${SUDO_USER}"
    else
        echo "/root"
    fi
}

writeClientConfig() {
    local client="$1"
    local filepath="${CLIENT_FILEPATH:-$(getHomeDir "$client")/$client.ovpn}"
    
    mkdir -p "$(dirname "$filepath")"
    cp /etc/openvpn/server/client-template.txt "$filepath"
    
    {
        echo "<ca>"
        cat /etc/openvpn/server/ca.crt 2>/dev/null
        echo "</ca>"
        echo "<cert>"
        cat "/etc/openvpn/server/easy-rsa/pki/issued/$client.crt" 2>/dev/null
        echo "</cert>"
        echo "<key>"
        cat "/etc/openvpn/server/easy-rsa/pki/private/$client.key" 2>/dev/null
        echo "</key>"
        
        if [[ -f /etc/openvpn/server/tls-crypt-v2.key ]]; then
            local tls_key
            tls_key=$(mktemp)
            openvpn --tls-crypt-v2 /etc/openvpn/server/tls-crypt-v2.key --genkey tls-crypt-v2-client "$tls_key"
            echo "<tls-crypt-v2>"
            cat "$tls_key"
            echo "</tls-crypt-v2>"
            rm -f "$tls_key"
        elif [[ -f /etc/openvpn/server/tls-crypt.key ]]; then
            echo "<tls-crypt>"
            cat /etc/openvpn/server/tls-crypt.key
            echo "</tls-crypt>"
        elif [[ -f /etc/openvpn/server/tls-auth.key ]]; then
            echo "key-direction 1"
            echo "<tls-auth>"
            cat /etc/openvpn/server/tls-auth.key
            echo "</tls-auth>"
        fi
    } >> "$filepath" 2>/dev/null
    
    GENERATED_CONFIG_PATH="$filepath"
}

newClient() {
    print_header "New Client"
    
    if [[ -z $CLIENT ]] || ! is_valid_client_name "$CLIENT"; then
        until is_valid_client_name "$CLIENT"; do
            read -rp "$(print_prompt "Client name: ")" CLIENT
        done
    fi
    
    cd /etc/openvpn/server/easy-rsa || exit
    
    if [[ -f "pki/issued/$CLIENT.crt" ]]; then
        log_fatal "Client $CLIENT already exists"
    fi
    
    export EASYRSA_CERT_EXPIRE=${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
    
    if [[ $PASS == "2" ]]; then
        if [[ -n "$PASSPHRASE" ]]; then
            export EASYRSA_PASSPHRASE="$PASSPHRASE"
            ./easyrsa --batch --passin=env:EASYRSA_PASSPHRASE --passout=env:EASYRSA_PASSPHRASE build-client-full "$CLIENT"
            unset EASYRSA_PASSPHRASE
        else
            ./easyrsa --batch build-client-full "$CLIENT"
        fi
    else
        ./easyrsa --batch build-client-full "$CLIENT" nopass
    fi
    
    writeClientConfig "$CLIENT"
    print_success "Client $CLIENT created: $GENERATED_CONFIG_PATH"
}

listClients() {
    print_header "Client List"
    
    if [[ ! -d /etc/openvpn/server/easy-rsa/pki ]]; then
        print_warning "No OpenVPN installation found"
        return
    fi
    
    local count=0
    echo ""
    while read -r line; do
        if [[ $line =~ ^V.*CN=([^/]+) ]]; then
            client="${BASH_REMATCH[1]}"
            [[ $client != server_* ]] && echo "    ✓ $client" && ((count++))
        fi
    done < /etc/openvpn/server/easy-rsa/pki/index.txt 2>/dev/null
    
    [[ $count -eq 0 ]] && print_warning "No clients found"
    echo ""
}

revokeClient() {
    print_header "Revoke Client"
    
    if [[ ! -f /etc/openvpn/server/easy-rsa/pki/index.txt ]]; then
        print_warning "No clients found"
        return
    fi
    
    local clients=()
    while read -r line; do
        if [[ $line =~ ^V.*CN=([^/]+) ]]; then
            client="${BASH_REMATCH[1]}"
            [[ $client != server_* ]] && clients+=("$client")
        fi
    done < /etc/openvpn/server/easy-rsa/pki/index.txt
    
    if [[ ${#clients[@]} -eq 0 ]]; then
        print_warning "No clients to revoke"
        return
    fi
    
    echo "Available clients:"
    for i in "${!clients[@]}"; do
        echo "  $((i+1))) ${clients[$i]}"
    done
    echo ""
    
    local choice
    read -rp "$(print_prompt "Select client [1-${#clients[@]}]: ")" choice
    [[ $choice =~ ^[0-9]+$ && $choice -ge 1 && $choice -le ${#clients[@]} ]] || log_fatal "Invalid selection"
    
    CLIENT="${clients[$((choice-1))]}"
    
    cd /etc/openvpn/server/easy-rsa || exit
    ./easyrsa --batch revoke "$CLIENT"
    ./easyrsa gen-crl
    cp pki/crl.pem /etc/openvpn/server/ 2>/dev/null
    
    print_success "Client $CLIENT revoked"
}

listConnectedClients() {
    print_header "Connected Clients"
    
    if [[ ! -f /var/log/openvpn/status.log ]]; then
        print_warning "Status file not found"
        return
    fi
    
    local count=0
    echo ""
    while IFS=',' read -r _ name real_addr _ _ _ _ connected _; do
        if [[ -n $name && $name != "Common Name" ]]; then
            echo "  • $name - $real_addr ($connected)"
            ((count++))
        fi
    done < <(grep "^CLIENT_LIST" /var/log/openvpn/status.log 2>/dev/null)
    
    [[ $count -eq 0 ]] && echo "  No clients currently connected"
    echo ""
    print_info "Note: Status updates every 60 seconds"
}

renewServer() {
    print_header "Renew Server Certificate"
    log_fatal "Not implemented yet"
}

# =============================================================================
# Uninstall Functions
# =============================================================================

removeUnbound() {
    rm -f /etc/unbound/unbound.conf.d/openvpn.conf
    read -rp "Remove Unbound completely? [y/N]: " REMOVE_UNBOUND
    if [[ $REMOVE_UNBOUND == "y" ]]; then
        systemctl stop unbound
        case $OS in
            debian|ubuntu) apt-get remove --purge -y unbound ;;
            centos|oracle) yum remove -y unbound ;;
            fedora|amzn2023) dnf remove -y unbound ;;
            arch) pacman -Rns --noconfirm unbound ;;
        esac
        rm -rf /etc/unbound
        print_success "Unbound removed"
    else
        systemctl restart unbound
    fi
}

removeOpenVPN() {
    print_header "Removing OpenVPN"
    
    read -rp "Really remove OpenVPN? [y/N]: " REMOVE
    [[ $REMOVE != "y" ]] && return
    
    systemctl stop openvpn-server@server 2>/dev/null
    systemctl disable openvpn-server@server 2>/dev/null
    
    case $OS in
        debian|ubuntu) apt-get remove --purge -y openvpn ;;
        centos|oracle) yum remove -y openvpn ;;
        fedora|amzn2023) dnf remove -y openvpn ;;
        arch) pacman -Rns --noconfirm openvpn ;;
    esac
    
    rm -rf /etc/openvpn /var/log/openvpn /etc/sysctl.d/99-openvpn.conf
    
    if [[ -f /etc/unbound/unbound.conf.d/openvpn.conf ]]; then
        removeUnbound
    fi
    
    # Remove firewall rules if iptables
    if command -v iptables &>/dev/null; then
        iptables -t nat -D POSTROUTING -s $VPN_SUBNET_IPV4/24 -o $NIC -j MASQUERADE 2>/dev/null
        iptables -D INPUT -i tun+ -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null
        iptables -D FORWARD -o tun+ -j ACCEPT 2>/dev/null
        iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT 2>/dev/null
    fi
    
    print_success "OpenVPN removed"
}

# =============================================================================
# Management Menu
# =============================================================================

manageMenu() {
    while true; do
        print_header "OpenVPN Management"
        
        echo ""
        print_menu_option "1" "Add a new client"
        print_menu_option "2" "List clients"
        print_menu_option "3" "Revoke client"
        print_menu_option "4" "List connected clients"
        print_menu_option "5" "Remove OpenVPN"
        print_menu_option "6" "Exit"
        echo ""
        
        read -rp "$(print_prompt "Select [1-6]: ")" choice
        
        case $choice in
            1) newClient ;;
            2) listClients ;;
            3) revokeClient ;;
            4) listConnectedClients ;;
            5) removeOpenVPN ;;
            6) exit 0 ;;
            *) print_warning "Invalid option" ;;
        esac
    done
}

# =============================================================================
# Command Handlers
# =============================================================================

parse_dns_provider() {
    local provider="$1"
    [[ -n "${DNS_PROVIDERS[$provider]}" || $provider == "custom" ]] && DNS="$provider" || log_fatal "Invalid DNS provider: $provider"
}

show_help() {
    cat <<EOF
${C_BOLD}${C_CYAN}OpenVPN Server Installer & Manager${C_RESET}

${C_BOLD}${C_YELLOW}Usage:${C_RESET} $SCRIPT_NAME <command> [options]

${C_BOLD}${C_GREEN}Commands:${C_RESET}
    install       Install and configure OpenVPN server
    uninstall     Remove OpenVPN server
    client        Manage client certificates
    server        Server management
    interactive   Launch interactive menu

${C_BOLD}${C_MAGENTA}Global Options:${C_RESET}
    --verbose     Show detailed output
    --log <path>  Log file path
    --no-log      Disable file logging
    --no-color    Disable colored output
    -h, --help    Show help

${C_DIM}Run '$SCRIPT_NAME <command> --help' for command-specific help.${C_RESET}
EOF
}

show_install_help() {
    cat <<EOF
${C_BOLD}${C_CYAN}Install OpenVPN${C_RESET}

Usage: $SCRIPT_NAME install [options]

Options:
    -i, --interactive     Run interactive install wizard
    --dns <provider>      DNS provider
    --dns-list            List available DNS providers
    --port <num>          OpenVPN port
    --no-client           Skip initial client creation
EOF
}

show_client_help() {
    cat <<EOF
${C_BOLD}${C_CYAN}Client Management${C_RESET}

Usage: $SCRIPT_NAME client <subcommand> [options]

Subcommands:
    add <name>     Add a new client
    list           List all clients
    revoke <name>  Revoke a client
EOF
}

show_client_add_help() {
    cat <<EOF
${C_BOLD}${C_CYAN}Add Client${C_RESET}

Usage: $SCRIPT_NAME client add <name> [options]

Options:
    --password [pass]   Password-protect client
    --output <path>     Output path for .ovpn file
EOF
}

show_client_list_help() {
    cat <<EOF
${C_BOLD}${C_CYAN}List Clients${C_RESET}

Usage: $SCRIPT_NAME client list [options]

Options:
    --format <fmt>  Output format: table or json
EOF
}

show_client_revoke_help() {
    cat <<EOF
${C_BOLD}${C_CYAN}Revoke Client${C_RESET}

Usage: $SCRIPT_NAME client revoke <name> [options]

Options:
    -f, --force   Skip confirmation
EOF
}

show_server_help() {
    cat <<EOF
${C_BOLD}${C_CYAN}Server Management${C_RESET}

Usage: $SCRIPT_NAME server <subcommand>

Subcommands:
    status   List connected clients
EOF
}

show_uninstall_help() {
    cat <<EOF
${C_BOLD}${C_CYAN}Uninstall OpenVPN${C_RESET}

Usage: $SCRIPT_NAME uninstall [options]

Options:
    -f, --force   Skip confirmation
EOF
}

list_dns_providers() {
    print_header "Available DNS Providers"
    echo ""
    for provider in "${!DNS_PROVIDERS[@]}"; do
        IFS='|' read -r name desc <<< "${DNS_PROVIDERS[$provider]}"
        printf "  ${C_GREEN}%-20s${C_RESET} ${C_DIM}%s${C_RESET}\n" "$provider" "$desc"
    done
    echo ""
}

cmd_install() {
    local interactive=false
    local no_client=false
    local list_dns=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interactive) interactive=true ;;
            --no-client) no_client=true ;;
            --dns-list) list_dns=true ;;
            --dns) shift; parse_dns_provider "$1" ;;
            --port) shift; PORT="$1" ;;
            -h|--help) show_install_help; exit 0 ;;
        esac
        shift
    done
    
    [[ $list_dns == true ]] && { list_dns_providers; exit 0; }
    
    requireNoOpenVPN
    
    if [[ $interactive == true ]]; then
        installQuestions
    else
        NON_INTERACTIVE_INSTALL=y
        APPROVE_INSTALL=y
        set_installation_defaults
        validate_configuration
        detect_server_ips
    fi
    
    NEW_CLIENT=$([[ $no_client == true ]] && echo "n" || echo "y")
    prepare_network_config
    installOpenVPN
}

cmd_uninstall() {
    local force=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--force) force=true ;;
            -h|--help) show_uninstall_help; exit 0 ;;
        esac
        shift
    done
    
    requireOpenVPN
    removeOpenVPN
}

cmd_client() {
    local subcmd="${1:-}"
    shift || true
    
    case "$subcmd" in
        add) cmd_client_add "$@" ;;
        list) cmd_client_list "$@" ;;
        revoke) cmd_client_revoke "$@" ;;
        renew) log_fatal "Not implemented" ;;
        ""|-h|--help) show_client_help ;;
        *) log_fatal "Unknown client subcommand: $subcmd" ;;
    esac
}

cmd_client_add() {
    local client_name=""
    local password_flag=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --password) password_flag=true; PASS=2 ;;
            --output) shift; CLIENT_FILEPATH="$1" ;;
            -h|--help) show_client_add_help; exit 0 ;;
            *) [[ -z "$client_name" ]] && client_name="$1" || log_fatal "Unknown: $1" ;;
        esac
        shift
    done
    
    [[ -z "$client_name" ]] && log_fatal "Client name required"
    validate_client_name "$client_name"
    requireOpenVPN
    
    CLIENT="$client_name"
    newClient
}

cmd_client_list() {
    local format="table"
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --format) shift; format="$1" ;;
            -h|--help) show_client_list_help; exit 0 ;;
        esac
        shift
    done
    
    requireOpenVPN
    OUTPUT_FORMAT="$format" listClients
}

cmd_client_revoke() {
    local client_name=""
    local force=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--force) force=true ;;
            -h|--help) show_client_revoke_help; exit 0 ;;
            *) [[ -z "$client_name" ]] && client_name="$1" || log_fatal "Unknown: $1" ;;
        esac
        shift
    done
    
    [[ -z "$client_name" ]] && log_fatal "Client name required"
    requireOpenVPN
    
    CLIENT="$client_name"
    revokeClient
}

cmd_server() {
    local subcmd="${1:-}"
    shift || true
    
    case "$subcmd" in
        status) listConnectedClients ;;
        renew) renewServer ;;
        ""|-h|--help) show_server_help ;;
        *) log_fatal "Unknown server subcommand: $subcmd" ;;
    esac
}

cmd_interactive() {
    if isOpenVPNInstalled; then
        manageMenu
    else
        installQuestions
        installOpenVPN
    fi
}

# =============================================================================
# Main Entry Point - IMPROVED: Runs interactive mode when no command given
# =============================================================================

SCRIPT_NAME="$(basename "$0")"

parse_args() {
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --verbose) VERBOSE=1 ;;
            --log) shift; LOG_FILE="$1" ;;
            --no-log) LOG_FILE="" ;;
            --no-color) NO_COLOR=1 ;;
            -h|--help) show_help; exit 0 ;;
            --) shift; break ;;
            -*) break ;;
            *) break ;;
        esac
        shift
    done
    
    local cmd="${1:-}"
    
    # If no command provided, run interactive mode
    if [[ -z "$cmd" ]]; then
        initialCheck
        cmd_interactive
        return
    fi
    
    # Shift past the command
    shift 2>/dev/null || true
    
    # Handle commands
    case "$cmd" in
        install) initialCheck; cmd_install "$@" ;;
        uninstall) initialCheck; cmd_uninstall "$@" ;;
        client) initialCheck; cmd_client "$@" ;;
        server) initialCheck; cmd_server "$@" ;;
        interactive) initialCheck; cmd_interactive "$@" ;;
        help|--help|-h) show_help ;;
        *) log_fatal "Unknown command: $cmd. Run '$SCRIPT_NAME --help' for usage." ;;
    esac
}

# Start the script
parse_args "$@"