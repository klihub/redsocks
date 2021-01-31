#!/bin/bash

set -e -o pipefail

SCRIPT_NAME=${0##*/}
CONFIG_FILE="/etc/sysconfig/redsocks-setup-proxy"

debug () {
    echo "$@" >> "$DEBUG_FILE"
}

info () {
    echo "I: $*"
}

warning () {
    echo "W: $*"
}

error () {
    echo "E: $*"
}

# Read the configuration, fill in defaults/fallbacks.
read_config () {
    if [ ! -f "$CONFIG_FILE" ]; then
        CONFIG_FILE=/etc/sysconfig/setup-proxy
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
        warning "can't configure proxying, missing $CONFIG_FILE"
        exit 0
    fi

    PROXY_ALWAYS_BYPASSS="
0.0.0.0/8
10.0.0.0/8
163.33.0.0/16
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
224.0.0.0/4
240.0.0.0/4
"

    . $CONFIG_FILE

    # fill in defaults/fallbacks
    CACHE_DIR=${CACHE_DIR:-/var/cache/redsocks-config}
    CACHE_FILE=${CACHE_FILE:-autoproxy}
    AUTOPROXY_TIMEOUT=${AUTOPROXY_TIMEOUT:-60}
    REDSOCKS_ADDRESS=${REDSOCKS_ADDRESS:-0.0.0.0}
    REDSOCKS_PORT=${REDSOCKS_PORT:-1080}
    REDSOCKS_TEMPLATE=${REDSOCKS_TEMPLATE:-/etc/redsocks/redsocks.conf.template}
    PROXY_ADDRESS=${PROXY_ADDRESS:-unset-proxy-address}
    PROXY_PORT=${PROXY_PORT:-1080}
    PROXY_TYPE=${PROXY_TYPE:-socks5}

    if [ -n "$DEBUG_FILE" -a -w "$DEBUG_FILE" ]; then
        alias debug='\debug'
    else
        alias debug=:
        DEBUG_FILE=/dev/null
    fi
}

# Fetch autoproxy configuration.
fetch_autoproxy () {
    local _cache=$CACHE_DIR/$CACHE_FILE.$(($(date -u +%s) / (24*60*60)))
    local _size _proxynet _timeout _elapsed

    mkdir -p $CACHE_DIR

    if [[ ! -f $_cache ]] || [[ "$(stat --printf=%s $_cache)" == 0 ]]; then
        rm -f $CACHE_DIR/$CACHE_FILE.* $CACHE_DIR/exceptions
        if ! wget --no-proxy --timeout=$AUTOPROXY_TIMEOUT -O$_cache $AUTOPROXY_URL; then
            return 1
        fi
    fi

    echo $_cache
}

# Generate an (proxying) exception list from autoproxy configuration.
generate_exceptions () {
    local _cache _retries

    # fetch autoproxy configuration
    _retries=0
    while [ "$_retries" -lt 5 ]; do
        if ! _cache=$(fetch_autoproxy); then
            let _retries=$_retries+1
            sleep 2
        else
            break
        fi
    done

    # Generate bypass rules for (local) network exceptions.
    (cat $_cache
     for _net in $PROXY_ALWAYS_BYPASS; do
         echo "$_net"
     done
     for _net in $PROXY_BYPASS; do
         echo "$_net"
     done) | /usr/bin/redsocks-proxynet | sort -u > $CACHE_DIR/exceptions
}

# Set up iptables with chains and rules for proxying.
iptables_init () {
    local _chain _dev

    info "Initializing iptables proxy chains..."

    # Create the necessary proxy chains for us.
    for _chain in PROXY PROXY_OUTPUT PROXY_FORWARD; do
        $xeq iptables -t nat -F $_chain 2> /dev/null || \
	    $xeq iptables -t nat -N $_chain
    done

    # Proxy the requested routed/forwarded devices.
    for _dev in $FORWARD_INTERFACES; do
	$xeq iptables -t nat -C PROXY_FORWARD \
             -p tcp -i $_dev -j PROXY 2> /dev/null || \
	    $xeq iptables -t nat -I PROXY_FORWARD \
                 -p tcp -i $_dev -j PROXY
    done

    # Proxy outgoing traffic.
    $xeq iptables -t nat -C PROXY_OUTPUT \
         \! -o lo -j PROXY 2> /dev/null || \
    $xeq iptables -t nat -I PROXY_OUTPUT \
         \! -o lo -j PROXY
    $xeq iptables -t nat -C OUTPUT \
         -p tcp -j PROXY_OUTPUT 2> /dev/null || \
    $xeq iptables -t nat -I OUTPUT \
         -p tcp -j PROXY_OUTPUT

    # Proxy forwarded traffic.
    $xeq iptables -t nat -C PREROUTING \
         -p tcp -j PROXY_FORWARD 2> /dev/null ||
    $xeq iptables -t nat -I PREROUTING \
         -p tcp -j PROXY_FORWARD


    # Create chains for filtering proxied forwarded traffic.
    for _chain in PROXY_FORWARD; do
        $xeq iptables -t filter -F $_chain 2> /dev/null || \
	    $xeq iptables -t filter -N $_chain
	$xeq iptables -t filter -P $_chain DROP
    done

    # Allow proxying traffic from the forwarded interfaces.
    for _dev in $FORWARD_INTERFACES; do
	$xeq iptables -t filter -C PROXY_FORWARD \
             -i $_dev -j ACCEPT 2> /dev/null ||
	    $xeq iptables -t filter -A PROXY_FORWARD \
                 -i $_dev -j ACCEPT
    done

    # Drive all proxied forwarded traffic through proxy filtering.
    $xeq iptables -t filter -I INPUT -p tcp --dport $REDSOCKS_PORT \
         -j PROXY_FORWARD
}

# Reset and remove iptables chains and rules for proxying.
iptables_reset () {
    local _chain _dev

    info "Resetting iptables proxy chains..."

    # Proxy the requested routed/forwarded devices.
    for _dev in $FORWARD_INTERFACES; do
	$xeq iptables -t nat -C PROXY_FORWARD \
             -p tcp -i $_dev -j PROXY 2> /dev/null && \
        $xeq iptables -t nat -D PROXY_FORWARD \
             -p tcp -i $_dev -j PROXY || :
    done

    # Disable outgoing traffic proxying.
    $xeq iptables -t nat -C PROXY_OUTPUT \
         \! -o lo -j PROXY 2> /dev/null && \
    $xeq iptables -t nat -D PROXY_OUTPUT \
         \! -o lo -j PROXY || :
    $xeq iptables -t nat -C OUTPUT \
         -p tcp -j PROXY_OUTPUT 2> /dev/null && \
    $xeq iptables -t nat -D OUTPUT \
         -p tcp -j PROXY_OUTPUT || :

    # Disable forwarded traffic proxying.
    $xeq iptables -t nat -C PREROUTING \
         -p tcp -j PROXY_FORWARD 2> /dev/null && \
    $xeq iptables -t nat -D PREROUTING \
         -p tcp -j PROXY_FORWARD

    # Flush and remove our proxy chains.
    for _chain in PROXY PROXY_OUTPUT PROXY_FORWARD; do
        $xeq iptables -t nat -F $_chain 2> /dev/null || :
    done
    for _chain in PROXY PROXY_OUTPUT PROXY_FORWARD; do
        $xeq iptables -t nat -X $_chain 2> /dev/null || :
    done

    # Flush our proxy filtering chains.
    for _chain in PROXY_FORWARD; do
        $xeq iptables -t filter -F $_chain 2> /dev/null
    done

    # Disable filtering of proxied forwarded traffic.
    $xeq iptables -t filter -C INPUT -p tcp --dport $REDSOCKS_PORT \
         -j PROXY_FORWARD 2> /dev/null && \
        $xeq iptables -t filter -D INPUT -p tcp --dport $REDSOCKS_PORT \
             -j PROXY_FORWARD 2> /dev/null
}

# Generate iptables rules for proxying.
iptables_proxy_rules () {
    local _exception _autoproxy

    info "Generating iptables proxy rules..."

    $xeq iptables -t nat -F PROXY || :
    cat $CACHE_DIR/exceptions | while read _exception; do
        $xeq iptables -t nat -C PROXY \
             -d "$_exception" -j RETURN 2> /dev/null || \
        $xeq iptables -t nat -A PROXY \
             -d "$_exception" -j RETURN || :
    done

    # Generate catch-all proxying rule.
    $xeq iptables -t nat -C PROXY \
         -p tcp -j REDIRECT --to-ports $REDSOCKS_PORT 2> /dev/null ||
    $xeq iptables -t nat -A PROXY \
         -p tcp -j REDIRECT --to-ports $REDSOCKS_PORT
}

# Flush the routing cache.
routing_flush () {
    $xeq ip route flush cache
}

# Generate redsocks configuration.
redsocks_config () {
    local _cfg=/etc/redsocks.conf
    local _sed _var _val _sep

    info "Generating redsocks configuration..."

    if [ -f $_cfg ]; then
        return 0
    fi

    # build sed replacement command
    for _var in REDSOCKS_{ADDRESS,PORT} PROXY_{ADDRESS,PORT,TYPE}; do
        _val="${!_var}"
        _sed="${_sed}${_sep}s/__${_var}__/${_val}/g"
        _sep=";"
    done
    # generate redsocks config file from template
    cat $REDSOCKS_TEMPLATE | sed "$_sed" > $_cfg
}

# Start redsocks proxy.
redsocks_start () {
    $xeq redsocks_config
    $xeq systemctl restart redsocks
}

# Stop redsocks proxy.
redsocks_stop () {
    $xeq systemctl stop redsocks
}

# Handle a device up event.
device_up () {
    routing_flush
    iptables_reset
    generate_exceptions
    iptables_init
    iptables_proxy_rules
    redsocks_start
}

# Handle a device down event.
device_down () {
    redsocks_stop
    routing_flush
    iptables_reset
}

# Handle a VPN device up event.
vpn_up () {
    :
}

# Handle a VPN device down event.
vpn_down () {
    :
}

# Flush iptables rules.
flush () {
    iptables_reset
}

# Process all hooks for a given action matching a given type ($type-$action-*).
run-hooks () {
    local _type=$1 _device=$2 _action=$3
    local _prefix=${_type}-${_action}- _fn

    echo "Running ${_prefix%-} hooks for $_device..."

    for _fn in $(declare -F | sed 's/^declare -[^ ]* *//g' | sort); do
        case $_fn in
            $_prefix*)
                $xeq $_fn $_device $_action || \
                    error "hook $_fn failed for $_device"
                ;;
            *)
                ;;
        esac
    done
}

# main proxy configuration
main-hook () {
    local _device=$1 _action=$2
    local _hook

    case $_action in
        up)       _hook=device_up;;
        down)     _hook=device_down;;
        vpn-up)   _hook=vpn_up;;
        vpn-down) _hook=vpn_down;;
        flush)    _hook=flush;;
        *)        exit 1;;
    esac

    $_hook $_device || error "$_device: $_hook failed"
}

# check if a givne interface is among the triggering ones
trigger-interface () {
    local _dev
    for _dev in $TRIGGER_INTERFACES; do
        case "$1" in
            $_dev) return 0;;
        esac
    done
    return 1
}

# Dump generic debugging information about this invocation.
dump_debug () {
    debug "===== $(date) $0 $* [$$] [device=$DEVICE_IFACE, action=$NM_DISPATCHER_ACTION] ====="
    env >> $DEBUG_FILE
}

#########################
# main script

while [ "${1#-}" != "$1" -a -n "$1" ]; do
    case $1 in
        --dry-run|-n) shift; xeq=echo;;
        --trace|-t) shift; set -x;;
    esac
done

read_config
dump_debug

if [ -n "$DEVICE_IFACE" ]; then
    device="$DEVICE_IFACE"
    action="$NM_DISPATCHER_ACTION"
else
    device="$1"
    action="$2"
fi


if ! trigger-interface "$device"; then
    exit 0
fi

case $0 in
    *prepare*)
        run-hooks prepare $device $action
        ;;
    *finalize*)
        run-hooks finalize $device $action
        ;;
    *)
        main-hook $device $action
        run-hooks main $device $action
        ;;
esac

exit 0

