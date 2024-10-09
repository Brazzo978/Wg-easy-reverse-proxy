#!/bin/bash

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

WG_CONFIG='/etc/wireguard/wg0.conf'
WG_INSTALLED_MARKER='/etc/wireguard/.wireguard_installed'
WG_INTERFACE='wg0'
PORT='51820'

function isRoot() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}You need to run this script as root${NC}"
        exit 1
    fi
}

function checkVirt() {
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
        echo -e "${RED}OpenVZ is not supported${NC}"
        exit 1
    fi

    if [ "$(systemd-detect-virt)" == "lxc" ]; then
        echo -e "${RED}LXC is not supported.${NC}"
        exit 1
    fi
}

function checkOS() {
    source /etc/os-release
    OS="${ID}"
    if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
        if [[ ${VERSION_ID} -lt 10 ]]; then
            echo -e "${RED}Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later${NC}"
            exit 1
        fi
        OS=debian # overwrite if raspbian
    elif [[ ${OS} == "ubuntu" ]]; then
        RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
        if [[ ${RELEASE_YEAR} -lt 18 ]]; then
            echo -e "${RED}Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Looks like you aren't running this installer on a Debian/Raspbian or Ubuntu system${NC}"
        exit 1
    fi
}

function install_wireguard() {
    isRoot
    checkVirt
    checkOS

    apt update
    apt install wireguard iptables socat -y
    mkdir -p /etc/wireguard
    chmod 600 /etc/wireguard

    # Parametri di configurazione del tunnel
    while true; do
        read -rp "IPv4 o IPv6 public address [$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)]: " SERVER_PUB_IP
        SERVER_PUB_IP=${SERVER_PUB_IP:-$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)}
        if [[ $SERVER_PUB_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || $SERVER_PUB_IP =~ ^([a-f0-9]{1,4}:){3,7}[a-f0-9]{1,4}$ ]]; then
            break
        else
            echo -e "${RED} invalid IP address ${NC}"
        fi
    done

    SERVER_PUB_NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

    SERVER_WG_NIC="wg0"

   while true; do
        read -rp "WireGuard server local IPv4 [10.0.0.1]: " SERVER_WG_IPV4
        SERVER_WG_IPV4=${SERVER_WG_IPV4:-10.0.0.1}
        if [[ $SERVER_WG_IPV4 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            break
        else
            echo -e "${RED} invalid IP address ${NC}"
        fi
    done

    while true; do
        read -rp "WireGuard server local IPv6 [fd42:42:42::1]: " SERVER_WG_IPV6
        SERVER_WG_IPV6=${SERVER_WG_IPV6:-fd42:42:42::1}
        if [[ $SERVER_WG_IPV6 =~ ^([a-f0-9]{1,4}:){3,7}[a-f0-9]{1,4}$ ]]; then
            break
        else
            echo -e "${RED} invalid IP address ${NC}"
        fi
    done

    while true; do
        RANDOM_PORT=$(shuf -i 65523-65535 -n 1)
        read -rp "Porta WireGuard [${RANDOM_PORT}]: " SERVER_PORT
        SERVER_PORT=${SERVER_PORT:-${RANDOM_PORT}}
        if [[ $SERVER_PORT =~ ^[0-9]+$ ]] && [ $SERVER_PORT -ge 65523 ] && [ $SERVER_PORT -le 65535 ]; then
            break
        else
            echo -e "${RED}Invalid port. port must be >= 65523 || <= 65535. Try again.${NC}"
        fi
    done

    # Genera chiavi per il server
    SERVER_PRIV_KEY=$(wg genkey)
    SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

    # Genera chiavi per il client
    CLIENT_PRIV_KEY=$(wg genkey)
    CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)

    # Crea configurazione WireGuard
    cat <<EOF > $WG_CONFIG
[Interface]
PrivateKey = $SERVER_PRIV_KEY
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = $SERVER_PORT
PostUp = iptables -A FORWARD -i $SERVER_PUB_NIC -o $SERVER_WG_NIC -j ACCEPT; iptables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -A FORWARD -i $SERVER_PUB_NIC -o $SERVER_WG_NIC -j ACCEPT; ip6tables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D FORWARD -i $SERVER_PUB_NIC -o $SERVER_WG_NIC -j ACCEPT; iptables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -D FORWARD -i $SERVER_PUB_NIC -o $SERVER_WG_NIC -j ACCEPT; ip6tables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE

[Peer]
# Client
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PSK
AllowedIPs = 10.0.0.2/32
EOF

    # Crea configurazione client
    cat <<EOF > ~/client-wg0.conf
[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = 10.0.0.2/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PSK
Endpoint = $SERVER_PUB_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0,::/0
EOF

    # Abilita IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
   # Avvia WireGuard
    wg-quick up $SERVER_WG_NIC
    systemctl enable wg-quick@$SERVER_WG_NIC

    # Crea file di marker per indicare che WireGuard è stato installato
    touch $WG_INSTALLED_MARKER
}

function setup_reverse_proxy() {
    while true; do
        read -p "Insert the client port to forward (eX: 80 for Http): " local_port
        if [[ $local_port =~ ^[0-9]+$ ]] && [ $local_port -ge 1 ] && [ $local_port -le 65522 ]; then
            break
        else
            echo -e "${ORANGE}Port must be lower than 65522. Try Again.${NC}"
        fi
    done

    while true; do
        read -p "Insert the local port to forward to client: " vps_port
        if [[ $vps_port =~ ^[0-9]+$ ]] && [ $vps_port -ge 1 ] && [ $vps_port -le 65522 ]; then
            break
        else
            echo -e "${ORANGE}Port must be lower than 65522. Try again.${NC}"
        fi
    done

    while true; do
        read -p "what protocol do you want to forward TCP, UDP or both? (tcp/udp/both): " protocol
        case "$protocol" in
            tcp)
                PROTOCOL_FLAG="TCP"
                break
                ;;
            udp)
                PROTOCOL_FLAG="UDP"
                break
                ;;
            both)
                PROTOCOL_FLAG="BOTH"
                break
                ;;
            *)
                echo -e "${ORANGE}Invalid option use 'tcp', 'udp' or 'both'.${NC}"
                ;;
        esac
    done

    # Imposta il reverse proxy usando systemd per renderlo persistente
    apt install socat -y

    if [[ "$PROTOCOL_FLAG" == "TCP" || "$PROTOCOL_FLAG" == "BOTH" ]]; then
        cat <<EOF > /etc/systemd/system/socat-proxy-tcp-${vps_port}.service
[Unit]
Description=Socat Reverse Proxy TCP from port ${vps_port} to local port ${local_port}
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:${vps_port},reuseaddr,fork TCP:10.0.0.2:${local_port}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl start socat-proxy-tcp-${vps_port}.service
        systemctl enable socat-proxy-tcp-${vps_port}.service
    fi

    if [[ "$PROTOCOL_FLAG" == "UDP" || "$PROTOCOL_FLAG" == "BOTH" ]]; then
        cat <<EOF > /etc/systemd/system/socat-proxy-udp-${vps_port}.service
[Unit]
Description=Socat Reverse Proxy UDP from port ${vps_port} to local port ${local_port}
After=network.target

[Service]
ExecStart=/usr/bin/socat UDP-LISTEN:${vps_port},reuseaddr,fork UDP:10.0.0.2:${local_port}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl start socat-proxy-udp-${vps_port}.service
        systemctl enable socat-proxy-udp-${vps_port}.service
    fi

    echo -e "${GREEN}Reverse proxy set on port ${vps_port} that forwards to port ${local_port} with protocol ${protocol}.${NC}"
    echo "${vps_port} -> ${local_port} (${protocol})" >> /etc/wireguard/forwarded_ports
}



function remove_reverse_proxy() {
    while true; do
        read -p "insert the port used in the vps side of the proxy you want to remove: " vps_port
        if [[ $vps_port =~ ^[0-9]+$ ]] && [ $vps_port -ge 1 ] && [ $vps_port -le 65535 ] && [ $vps_port -ne $PORT ] && [ $vps_port -ne 65522 ]; then
            break
        else
            echo -e "${ORANGE}Invalid Port. Try again.${NC}"
        fi
    done

    # Identifica i protocolli da rimuovere
    protocols=$(grep "^${vps_port} ->" /etc/wireguard/forwarded_ports | awk -F' ' '{print $3}' | tr ',' ' ')
    
    # Rimuove il servizio systemd per ogni protocollo identificato
    for protocol in $protocols; do
        systemctl stop socat-proxy-${vps_port}-${protocol}.service
        systemctl disable socat-proxy-${vps_port}-${protocol}.service
        rm /etc/systemd/system/socat-proxy-${vps_port}-${protocol}.service
    done

    # Ricarica i servizi di systemd
    systemctl daemon-reload

    # Rimuovi la porta dall'elenco dei proxy inoltrati
    sed -i "/${vps_port} ->/d" /etc/wireguard/forwarded_ports

    echo -e "${GREEN}Reverse proxy on port ${vps_port} removed successfully.${NC}"
}

function list_reverse_proxy() {
    if [ -f /etc/wireguard/forwarded_ports ]; then
        echo -e "${GREEN}Active reverse proxy list:${NC}"
        while IFS= read -r line; do
            echo -e "${GREEN}${line}${NC}"
        done < /etc/wireguard/forwarded_ports
    else
        echo -e "${ORANGE}No proxy found.${NC}"
    fi
}

function check_tunnel_status() {
    if wg show $WG_INTERFACE > /dev/null 2>&1; then
        echo -e "${GREEN}WireGuard tunnel (${WG_INTERFACE}) is working.${NC}"
    else
        echo -e "${RED}Wireguard tunnel (${WG_INTERFACE}) is not working.${NC}"
        read -p "Do  you want to try restarting it ? (y/n): " response
        if [[ "$response" =~ ^[nN]$ ]]; then
            systemctl restart wg-quick@${WG_INTERFACE}
            if wg show $WG_INTERFACE > /dev/null 2>&1; then
                echo -e "${GREEN}Wireguard tunnel (${WG_INTERFACE}) was restarted and now is working.${NC}"
            else
                echo -e "${RED}Error while restarting the tunnel , check the log for more details.${NC}"
            fi
        fi
    fi
}


function uninstall_wireguard() {
    # Disattiva il tunnel WireGuard
    wg-quick down $WG_INTERFACE

    # Disattiva e rimuovi tutti i servizi di reverse proxy attivi
    if [ -f /etc/wireguard/forwarded_ports ]; then
        while IFS= read -r line; do
            vps_port=$(echo "$line" | cut -d' ' -f1)
            systemctl stop socat-proxy-${vps_port}.service
            systemctl disable socat-proxy-${vps_port}.service
            rm /etc/systemd/system/socat-proxy-${vps_port}.service
        done < /etc/wireguard/forwarded_ports
        systemctl daemon-reload
        rm /etc/wireguard/forwarded_ports
    fi

    # Rimuove WireGuard e i relativi file di configurazione
    apt remove --purge -y wireguard
    rm -rf /etc/wireguard

    # Rimuovi il file di marker per indicare che WireGuard è stato disinstallato
    rm -f $WG_INSTALLED_MARKER

    echo -e "${GREEN}Wireguard and the reverse proxy have been removed sucessfully.${NC}"
}

function manageMenu() {
    echo "Welcome"
    echo "What you want to do?"
    echo "   1) Check wireguard status"
    echo "   2) Add a new reverse proxy"
    echo "   3) List current reverse proxy"
    echo "   4) Remove a reverse proxy"
    echo "   5) Uninstall everything"
    echo "   6) Exit"
    
    until [[ ${MENU_OPTION} =~ ^[1-6]$ ]]; do
        read -rp "Seleziona un'opzione [1-6]: " MENU_OPTION
    done
    
    case "${MENU_OPTION}" in
    1)
        check_tunnel_status
        ;;
    2)
        setup_reverse_proxy
        ;;
    3)
        list_reverse_proxy
        ;;
    4)
        remove_reverse_proxy
        ;;
    5)
        uninstall_wireguard
        ;;
    6)
        exit 0
        ;;
    esac
}




initialCheck() {
    isRoot
    checkVirt
    checkOS
}

# Inizializza il setup
initialCheck

# Controlla se WireGuard è già installato
if [ -f "$WG_INSTALLED_MARKER" ] && [ -d "/etc/wireguard" ]; then
    manageMenu
else
    install_wireguard
fi
