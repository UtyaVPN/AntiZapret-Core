#!/bin/bash
#
# Скрипт для установки на своём сервере AntiZapret-Core
#
# https://github.com/UtyaDev/AntiZapret-Core
#

export LC_ALL=C

# Проверка прав root
if [[ "$EUID" -ne 0 ]]; then
	echo 'Error: You need to run this as root!'
	exit 2
fi

cd /root

# Проверка на OpenVZ и LXC
if [[ "$(systemd-detect-virt)" == "openvz" || "$(systemd-detect-virt)" == "lxc" ]]; then
	echo 'Error: OpenVZ and LXC are not supported!'
	exit 3
fi

# Проверка версии системы
OS="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
VERSION="$(lsb_release -rs | cut -d '.' -f1)"

if [[ "$OS" == "debian" ]]; then
	if [[ "$VERSION" != "11" ]] && [[ "$VERSION" != "12" ]]; then
		echo "Error: Debian $VERSION is not supported! Only versions 11 and 12 are allowed"
		exit 4
	fi
elif [[ "$OS" == "ubuntu" ]]; then
	if [[ "$VERSION" != "22" ]] && [[ "$VERSION" != "24" ]]; then
		echo "Error: Ubuntu $VERSION is not supported! Only versions 22 and 24 are allowed"
		exit 5
	fi
elif [[ "$OS" != "debian" ]] && [[ "$OS" != "ubuntu" ]]; then
	echo "Error: Your Linux distribution ($OS) is not supported!"
	exit 6
fi

# Проверка свободного места (минимум 2Гб)
if [[ $(df --output=avail / | tail -n 1) -lt $((2 * 1024 * 1024)) ]]; then
	echo 'Error: Low disk space! You need 2GB of free space!'
	exit 7
fi

# Проверка наличия сетевого интерфейса и IPv4-адреса
DEFAULT_INTERFACE="$(ip route get 1.2.3.4 2>/dev/null | awk '{print $5; exit}')"
if [[ -z "$DEFAULT_INTERFACE" ]]; then
	echo 'Default network interface not found!'
	exit 8
fi

DEFAULT_IP="$(ip route get 1.2.3.4 2>/dev/null | awk '{print $7; exit}')"
if [[ -z "$DEFAULT_IP" ]]; then
	echo 'Default IPv4 address not found!'
	exit 9
fi

echo
echo -e '\e[1;32mInstalling AntiZapret-Core...\e[0m'
echo 'More details: https://github.com/UtyaDev/AntiZapret-Core'
echo

MTU=$(< /sys/class/net/"$DEFAULT_INTERFACE"/mtu)
if (( MTU < 1500 )); then
	echo "Warning! Low MTU on $DEFAULT_INTERFACE: $MTU"
	echo
fi

# Спрашиваем о настройках
echo
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
echo 'Default DNS  address:     10.77.77.77'
echo 'Alternative DNS address: 172.77.77.77'
until [[ "$ALTERNATIVE_IP" =~ (y|n) ]]; do
	read -rp 'Use alternative range of IP addresses? [y/n]: ' -e -i n ALTERNATIVE_IP
done
echo
[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"
echo "Default FAKE IP address range:     $IP.30.0.0/15"
echo 'Alternative FAKE IP address range: 198.18.0.0/15'
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
echo 'Installation, please wait...'

# Ожидание пока выполняется apt-get
while pidof apt-get &>/dev/null; do
	echo 'Waiting for apt-get to finish...';
	sleep 5;
done

# Остановим и выключим обновляемые службы
systemctl disable --now kresd@1 2>/dev/null
systemctl disable --now kresd@2 2>/dev/null
systemctl disable --now antizapret 2>/dev/null
systemctl disable --now antizapret-update.timer 2>/dev/null
systemctl disable --now antizapret-update 2>/dev/null

# SSH protection включён
if [[ "$SSH_PROTECTION" == "y" ]]; then
	apt-get purge -y fail2ban || true
	apt-get purge -y sshguard || true
fi

# Удаляем кэш Knot Resolver
rm -rf /var/cache/knot-resolver/*
rm -rf /var/cache/knot-resolver2/*

# Принудительная загрузка модуля nf_conntrack
echo "nf_conntrack" > /etc/modules-load.d/nf_conntrack.conf

# Завершим выполнение скрипта при ошибке
set -e

# Обработка ошибок
handle_error() {
	echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

# Обновляем систему
rm -rf /etc/apt/sources.list.d/cznic-labs-knot-resolver.list
export DEBIAN_FRONTEND=noninteractive
apt-get clean
apt-get update
dpkg --configure -a
apt-get install --fix-broken -y
apt-get dist-upgrade -y
apt-get install --reinstall -y curl gpg

# Папка для ключей
mkdir -p /etc/apt/keyrings

# Добавим репозиторий Knot Resolver
curl -fsSL https://pkg.labs.nic.cz/gpg -o /etc/apt/keyrings/cznic-labs-pkg.gpg
echo "deb [signed-by=/etc/apt/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver $(lsb_release -cs) main" > /etc/apt/sources.list.d/cznic-labs-knot-resolver.list

# Добавим репозиторий Debian Backports
if [[ "$OS" == "debian" ]]; then
	if [[ "$VERSION" -ge 12 ]]; then
		echo "deb http://deb.debian.org/debian $(lsb_release -cs)-backports main" > /etc/apt/sources.list.d/backports.list
	elif [[ "$VERSION" -eq 11 ]]; then
		echo "deb http://archive.debian.org/debian $(lsb_release -cs)-backports main" > /etc/apt/sources.list.d/backports.list
	fi
fi

# Ставим необходимые пакеты
apt-get update
apt-get install --reinstall -y git iptables gawk knot-resolver idn sipcalc python3-pip diffutils socat lua-cqueues ipset irqbalance
apt-get autoremove --purge -y
apt-get clean

# Клонируем репозиторий и устанавливаем dnslib
rm -rf /tmp/dnslib
git clone https://github.com/paulc/dnslib.git /tmp/dnslib
PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install --force-reinstall --user /tmp/dnslib

# Клонируем репозиторий antizapret
rm -rf /tmp/antizapret
git clone https://github.com/UtyaDev/AntiZapret-Core.git /tmp/antizapret

# Сохраняем пользовательские настройки
mkdir -p /tmp/antizapret/setup/root/antizapret/config/manual
mkdir -p /tmp/antizapret/setup/root/antizapret/config/sources
cp -r /root/antizapret/config/manual/* /tmp/antizapret/setup/root/antizapret/config/manual/ 2>/dev/null || true
cp -r /root/antizapret/config/sources/* /tmp/antizapret/setup/root/antizapret/config/sources/ 2>/dev/null || true
cp /etc/knot-resolver/*.lua /tmp/antizapret/setup/etc/knot-resolver/ || true

# Сохраняем настройки
echo "SETUP_DATE=$(date --iso-8601=seconds)
ANTIZAPRET_DNS=$ANTIZAPRET_DNS
ALTERNATIVE_IP=$ALTERNATIVE_IP
ALTERNATIVE_FAKE_IP=$ALTERNATIVE_FAKE_IP
SSH_PROTECTION=$SSH_PROTECTION
ATTACK_PROTECTION=$ATTACK_PROTECTION
CLEAR_HOSTS=y" > /tmp/antizapret/setup/root/antizapret/setup

# Создаем папки для кэша Knot Resolver
mkdir -p /var/cache/knot-resolver
mkdir -p /var/cache/knot-resolver2
chown -R knot-resolver:knot-resolver /var/cache/knot-resolver
chown -R knot-resolver:knot-resolver /var/cache/knot-resolver2

# Выставляем разрешения
find /tmp/antizapret -type f -exec chmod 644 {} +
find /tmp/antizapret -type d -exec chmod 755 {} +
find /tmp/antizapret/setup/root/antizapret -type f -exec chmod +x {} +

# Копируем нужное, удаляем не нужное
find /tmp/antizapret -name '.gitkeep' -delete
rm -rf /root/antizapret
cp -r /tmp/antizapret/setup/* /
rm -rf /tmp/dnslib
rm -rf /tmp/antizapret

# Настраиваем DNS в AntiZapret-Core
if [[ "$ANTIZAPRET_DNS" == "2" ]]; then
	# SkyDNS
	sed -i "s/{'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'}/'127.0.0.1'/" /etc/knot-resolver/kresd.conf
	sed -i "s/{'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'}/'193.58.251.251'/" /etc/knot-resolver/kresd.conf
elif [[ "$ANTIZAPRET_DNS" == "3" ]]; then
	# Cloudflare+Quad9
	sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'/'1.1.1.1', '1.0.0.1', '9.9.9.10', '149.112.112.10'/" /etc/knot-resolver/kresd.conf
elif [[ "$ANTIZAPRET_DNS" == "4" ]]; then
	# Comss
	sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'/'83.220.169.155', '212.109.195.93', '195.133.25.16'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'83.220.169.155', '212.109.195.93', '195.133.25.16'/" /etc/knot-resolver/kresd.conf
elif [[ "$ANTIZAPRET_DNS" == "5" ]]; then
	# XBox
	sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'/'176.99.11.77', '80.78.247.254', '31.192.108.180'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'176.99.11.77', '80.78.247.254', '31.192.108.180'/" /etc/knot-resolver/kresd.conf
elif [[ "$ANTIZAPRET_DNS" == "6" ]]; then
	# Malw
	sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'/'84.21.189.133', '193.23.209.189'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'84.21.189.133', '193.23.209.189'/" /etc/knot-resolver/kresd.conf
fi

# Используем альтернативные диапазоны подменных IPv4-адресов
# 10(172).30.0.0/15 => 198.18.0.0/15
if [[ "$ALTERNATIVE_FAKE_IP" == "y" ]]; then
	sed -i 's/10\.30\./198\.18\./g' /root/antizapret/proxy.py
fi

# Используем альтернативные диапазоны IPv4-адресов
# 10.77.77.77 => 172.77.77.77/15
if [[ "$ALTERNATIVE_IP" == "y" ]]; then
	sed -i 's/10\./172\./g' /root/antizapret/proxy.py
	sed -i 's/10\./172\./g' /etc/knot-resolver/kresd.conf
fi

# Загружаем и создаем списки исключений
/root/antizapret/doall.sh noclear

# Включим обновляемые службы
systemctl enable kresd@1
systemctl enable kresd@2
systemctl enable antizapret
systemctl enable antizapret-update.timer
systemctl enable antizapret-update

ERRORS=""

# Если есть ошибки, выводим их
if [[ -n "$ERRORS" ]]; then
	echo -e "$ERRORS"
fi

# Создадим файл подкачки размером 1 Гб если его нет
if [[ -z "$(swapon --show)" ]]; then
	set +e
	SWAPFILE="/swapfile"
	SWAPSIZE=1024
	dd if=/dev/zero of="$SWAPFILE" bs=1M count="$SWAPSIZE"
	chmod 600 "$SWAPFILE"
	mkswap "$SWAPFILE"
	swapon "$SWAPFILE"
	echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
fi

# Перезагружаем
echo
echo -e '\e[1;32mAntiZapret-Core installed successfully!\e[0m'
echo 'Rebooting...'

reboot
