#!/bin/bash
export LC_ALL=C

# Проверка необходимости перезагрузить
if [[ -f /var/run/reboot-required ]] || pidof apt apt-get dpkg unattended-upgrades >/dev/null 2>&1; then
	echo 'Error: You need to reboot this server before installation!'
	exit 2
fi

# Проверка прав root
if [[ "$EUID" -ne 0 ]]; then
	echo 'Error: You need to run this as root!'
	exit 3
fi

cd /root

if [[ "$(systemd-detect-virt)" == "openvz" || "$(systemd-detect-virt)" == "lxc" ]]; then
    echo 'Error: OpenVZ and LXC are not supported!'
    exit 4
fi

OS="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
VERSION="$(lsb_release -rs | cut -d '.' -f1)"

if [[ "$OS" == "debian" ]]; then
    if [[ "$VERSION" != "11" && "$VERSION" != "12" ]]; then
        echo "Error: Debian $VERSION is not supported! Only versions 11 and 12 are allowed"
        exit 5
    fi
elif [[ "$OS" == "ubuntu" ]]; then
    if [[ "$VERSION" != "22" && "$VERSION" != "24" ]]; then
        echo "Error: Ubuntu $VERSION is not supported! Only versions 22 and 24 are allowed"
        exit 6
    fi
else
    echo "Error: Your Linux distribution ($OS) is not supported!"
    exit 7
fi

if [[ $(df --output=avail / | tail -n 1) -lt $((2 * 1024 * 1024)) ]]; then
    echo 'Error: Low disk space! You need 2GB of free space!'
    exit 8
fi

DEFAULT_INTERFACE="$(ip route get 1.2.3.4 2>/dev/null | awk '{print $5; exit}')"
if [[ -z "$DEFAULT_INTERFACE" ]]; then
    echo 'Default network interface not found!'
    exit 9
fi

DEFAULT_IP="$(ip route get 1.2.3.4 2>/dev/null | awk '{print $7; exit}')"
if [[ -z "$DEFAULT_IP" ]]; then
    echo 'Default IPv4 address not found!'
    exit 10
fi

echo -e '\n\e[1;32mInstalling AntiZapret-Core...\e[0m'
echo -e 'More details: https://github.com/UtyaDev/AntiZapret-Core\n'

MTU=$(< "/sys/class/net/$DEFAULT_INTERFACE/mtu")
if (( MTU < 1500 )); then
    echo -e "Warning! Low MTU on $DEFAULT_INTERFACE: $MTU\n"
fi

echo -e 'Choose DNS resolvers for \e[1;32mAntiZapret-Core\e[0m:'
echo '    1) Cloudflare+Quad9  - Recommended by default'
echo '       +MSK-IX+SkyDNS *'
echo '    2) SkyDNS *          - Recommended for expert users if this server IP is registered in SkyDNS'
echo '                           Register account (Family plan) and add this server IP at https://skydns.ru'
echo '    3) Cloudflare+Quad9  - Use if default choice fails to resolve domains'
echo '    4) Comss **          - More details: https://comss.ru/disqus/page.php?id=7315'
echo '    5) XBox **           - More details: https://xbox-dns.ru'
echo '    6) Malw **           - More details: https://info.dns.malw.link'
echo
echo '  * - DNS resolvers optimized for users located in Russia'
echo ' ** - Enable additional proxying and hide this server IP on some internet resources'
echo '      Use only if this server is geolocated in Russia or problems accessing some internet resources'

until [[ "$ANTIZAPRET_DNS" =~ ^[1-6]$ ]]; do
    read -rp 'DNS choice [1-6]: ' -e -i 1 ANTIZAPRET_DNS
done

echo
echo 'Default DNS address:      10.77.77.77'
echo 'Alternative DNS address:  172.77.77.77'
until [[ "$ALTERNATIVE_IP" =~ (y|n) ]]; do
    read -rp 'Use alternative range of IP addresses? [y/n]: ' -e -i n ALTERNATIVE_IP
done

echo
[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"
echo "Default FAKE IP address range:      $IP.30.0.0/15"
echo 'Alternative FAKE IP address range:  198.18.0.0/15'
until [[ "$ALTERNATIVE_FAKE_IP" =~ (y|n) ]]; do
    read -rp 'Use alternative range of FAKE IP addresses? [y/n]: ' -e -i y ALTERNATIVE_FAKE_IP
done

echo
until [[ "$SSH_PROTECTION" =~ (y|n) ]]; do
    read -rp 'Enable SSH brute-force protection? [y/n]: ' -e -i y SSH_PROTECTION
done

echo
echo "Warning! Network attack and scan protection may block VPN or third-party applications!"
until [[ "$ATTACK_PROTECTION" =~ (y|n) ]]; do
    read -rp 'Enable network attack and scan protection? [y/n]: ' -e -i y ATTACK_PROTECTION
done

echo
echo "Route aggregation reduces the number of routes for hardware routers compatibility."
echo "Enter the maximum number of routes (e.g., 500). Enter 0 to disable aggregation."
until [[ "$ROUTE_AGGREGATION_LIMIT" =~ ^[0-9]+$ ]]; do
    read -rp 'Route aggregation limit: ' -e -i 500 ROUTE_AGGREGATION_LIMIT
done

echo -e '\nInstallation, please wait...'

while pidof apt-get &>/dev/null; do
    echo 'Waiting for apt-get to finish...'
    sleep 5
done

systemctl disable --now kresd@1 kresd@2 antizapret antizapret-update.timer antizapret-update 2>/dev/null || true

if [[ "$SSH_PROTECTION" == "y" ]]; then
    apt-get purge -y fail2ban sshguard || true
fi

rm -rf /var/cache/knot-resolver/* /var/cache/knot-resolver2/*
echo "nf_conntrack" > /etc/modules-load.d/nf_conntrack.conf

set -e
handle_error() {
    echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
    echo -e "\e[1;31mError at line $1: $2\e[0m"
    exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

rm -rf /etc/apt/sources.list.d/cznic-labs-knot-resolver.list
export DEBIAN_FRONTEND=noninteractive
apt-get clean
apt-get update
dpkg --configure -a
apt-get install --fix-broken -y
apt-get dist-upgrade -y
apt-get install --reinstall -y curl gpg

mkdir -p /etc/apt/keyrings
curl -fsSL https://pkg.labs.nic.cz/gpg -o /etc/apt/keyrings/cznic-labs-pkg.gpg
echo "deb [signed-by=/etc/apt/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver $(lsb_release -cs) main" > /etc/apt/sources.list.d/cznic-labs-knot-resolver.list

if [[ "$OS" == "debian" ]]; then
    if [[ "$VERSION" -ge 12 ]]; then
        echo "deb http://deb.debian.org/debian $(lsb_release -cs)-backports main" > /etc/apt/sources.list.d/backports.list
    elif [[ "$VERSION" -eq 11 ]]; then
        echo "deb http://archive.debian.org/debian $(lsb_release -cs)-backports main" > /etc/apt/sources.list.d/backports.list
    fi
fi

apt-get update
apt-get install --reinstall -y git iptables gawk knot-resolver idn sipcalc python3-pip diffutils socat lua-cqueues ipset irqbalance unattended-upgrades
apt-get autoremove --purge -y
apt-get clean
dpkg-reconfigure -f noninteractive unattended-upgrades

rm -rf /tmp/antizapret
PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install --user dnslib py-radix
git clone https://github.com/UtyaDev/AntiZapret-Core.git /tmp/antizapret

mkdir -p /tmp/antizapret/setup/root/antizapret/config/{manual,sources}
cp -r /root/antizapret/config/manual/* /tmp/antizapret/setup/root/antizapret/config/manual/ 2>/dev/null || true
cp -r /root/antizapret/config/sources/* /tmp/antizapret/setup/root/antizapret/config/sources/ 2>/dev/null || true
cp /etc/knot-resolver/*.lua /tmp/antizapret/setup/etc/knot-resolver/ || true

echo "SETUP_DATE=$(date --iso-8601=seconds)
ANTIZAPRET_DNS=$ANTIZAPRET_DNS
ALTERNATIVE_IP=$ALTERNATIVE_IP
ALTERNATIVE_FAKE_IP=$ALTERNATIVE_FAKE_IP
SSH_PROTECTION=$SSH_PROTECTION
ATTACK_PROTECTION=$ATTACK_PROTECTION
CLEAR_HOSTS=y
ROUTE_AGGREGATION_LIMIT=$ROUTE_AGGREGATION_LIMIT" > /tmp/antizapret/setup/root/antizapret/setup

mkdir -p /var/cache/knot-resolver /var/cache/knot-resolver2
chown -R knot-resolver:knot-resolver /var/cache/knot-resolver /var/cache/knot-resolver2

find /tmp/antizapret -type f -exec chmod 644 {} +
find /tmp/antizapret -type d -exec chmod 755 {} +
find /tmp/antizapret/setup/root/antizapret -type f -exec chmod +x {} +
find /tmp/antizapret -name '.gitkeep' -delete

rm -rf /root/antizapret
cp -r /tmp/antizapret/setup/* /
rm -rf /tmp/dnslib /tmp/antizapret

/root/antizapret/doall.sh noclear
systemctl enable --now kresd@1 kresd@2 antizapret antizapret-update.timer antizapret-update

if [[ -z "$(swapon --show)" ]]; then
    set +e
    dd if=/dev/zero of=/swapfile bs=1M count=1024
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi

echo -e '\n\e[1;32mAntiZapret-Core installed successfully!\e[0m'
echo 'Rebooting...'
reboot
