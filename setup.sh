#!/bin/bash
#
# Скрипт для установки AntiZapret-Core (Smart DNS + Fake IP)
#
# https://github.com/UtyaVPN/AntiZapret-Core
#

export LC_ALL=C

#
# Проверка прав root
if [[ "$EUID" -ne 0 ]]; then
	echo 'Error: You need to run this as root!'
	exit 2
fi

cd /root

#
# Проверка версии системы
OS="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
VERSION="$(lsb_release -rs | cut -d '.' -f1)"

if [[ "$OS" == "debian" ]]; then
	if [[ $VERSION -lt 11 ]]; then
		echo 'Error: Your Debian version is not supported!'
		exit 4
	fi
elif [[ "$OS" == "ubuntu" ]]; then
	if [[ $VERSION -lt 22 ]]; then
		echo 'Error: Your Ubuntu version is not supported!'
		exit 5
	fi
elif [[ "$OS" != "debian" ]] && [[ "$OS" != "ubuntu" ]]; then
	echo 'Error: Your Linux version is not supported!'
	exit 6
fi

echo
echo -e '\e[1;32mInstalling AntiZapret-Core...\e[0m'
echo 'Smart DNS + Fake IP'
echo

#
# Спрашиваем о настройках
echo
echo -e 'Choose DNS resolvers for \e[1;32mAntiZapret-Core\e[0m:'
echo '    1) Cloudflare+Quad9  - Recommended by default'
echo '        +MSK-IX+NSDI *'
echo '    2) Cloudflare+Quad9  - Use if default choice fails to resolve domains'
echo '    3) Comss **          - More details: https://comss.ru/disqus/page.php?id=7315'
echo '    4) Xbox **           - More details: https://xbox-dns.ru'
echo '    5) Malw **           - More details: https://info.dns.malw.link'
echo
echo '  * - DNS resolvers optimized for users located in Russia'
echo ' ** - Enable additional proxying and hide this server IP on some internet resources'
echo '      Use only if this server is geolocated in Russia or problems accessing some internet resources'
until [[ "$ANTIZAPRET_DNS" =~ ^[1-5]$ ]]; do
	read -rp 'DNS choice [1-5]: ' -e -i 1 ANTIZAPRET_DNS
done
echo
until [[ "$BLOCK_ADS" =~ (y|n) ]]; do
	read -rp $'Enable blocking ads, trackers, malware and phishing websites based on AdGuard and OISD rules? [y/n]: ' -e -i y BLOCK_ADS
done
echo
echo 'Default IP address range:      10.28.0.0/14'
echo 'Alternative IP address range: 172.28.0.0/14'
until [[ "$ALTERNATIVE_IP" =~ (y|n) ]]; do
	read -rp 'Use alternative range of IP addresses? [y/n]: ' -e -i n ALTERNATIVE_IP
done
echo

until [[ "$ROUTE_ALL" =~ (y|n) ]]; do
	read -rp $'Route all traffic for domains via AntiZapret, excluding Russian domains and domains from config/exclude-hosts.txt? [y/n]: ' -e -i n ROUTE_ALL
done
echo
until [[ "$DISCORD_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Discord voice IPs? [y/n]: ' -e -i y DISCORD_INCLUDE
done
echo
until [[ "$CLOUDFLARE_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Cloudflare IPs? [y/n]: ' -e -i y CLOUDFLARE_INCLUDE
done
echo
until [[ "$TELEGRAM_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Telegram IPs? [y/n]: ' -e -i y TELEGRAM_INCLUDE
done
echo
until [[ "$AMAZON_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Amazon IPs? [y/n]: ' -e -i n AMAZON_INCLUDE
done
echo
until [[ "$HETZNER_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Hetzner IPs? [y/n]: ' -e -i n HETZNER_INCLUDE
done
echo
until [[ "$DIGITALOCEAN_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include DigitalOcean IPs? [y/n]: ' -e -i n DIGITALOCEAN_INCLUDE
done
echo
until [[ "$OVH_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include OVH IPs? [y/n]: ' -e -i n OVH_INCLUDE
done
echo
until [[ "$GOOGLE_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Google IPs? [y/n]: ' -e -i n GOOGLE_INCLUDE
done
echo
until [[ "$AKAMAI_INCLUDE" =~ (y|n) ]]; do
	read -rp $'Include Akamai IPs? [y/n]: ' -e -i n AKAMAI_INCLUDE
done
echo
until [[ "$CLEAR_HOSTS" =~ (y|n) ]]; do
	read -rp $'Remove gambling and betting domains? [y/n]: ' -e -i y CLEAR_HOSTS
done

#
# Определяем интерфейс и IP
DEFAULT_INTERFACE=$(ip route get 1.2.3.4 | awk '{print $5; exit}')
DEFAULT_IP=$(ip route get 1.2.3.4 | awk '{print $7; exit}')

#
# Ожидание пока выполняется apt-get
while pidof apt-get &>/dev/null; do
	echo 'Waiting for apt-get to finish...';
	sleep 5;
done

#
# Отключим фоновые обновления системы
systemctl stop unattended-upgrades &>/dev/null
systemctl stop apt-daily.timer &>/dev/null
systemctl stop apt-daily-upgrade.timer &>/dev/null

#
# Остановим и выключим обновляемые службы
systemctl disable --now kresd@1 &>/dev/null
systemctl disable --now kresd@2 &>/dev/null
systemctl disable --now antizapret &>/dev/null
systemctl disable --now antizapret-update &>/dev/null
systemctl disable --now antizapret-update.timer &>/dev/null

#
# Удаляем кэш Knot Resolver
rm -rf /var/cache/knot-resolver/*
rm -rf /var/cache/knot-resolver2/*

#
# Завершим выполнение скрипта при ошибке
set -e

#
# Обработка ошибок
handle_error() {
	echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

#
# Обновляем систему
rm -rf /etc/apt/sources.list.d/cznic-labs-knot-resolver.list
export DEBIAN_FRONTEND=noninteractive
apt-get clean
apt-get update
dpkg --configure -a
apt-get install --fix-broken -y
apt-get dist-upgrade -y
apt-get install --reinstall -y curl gpg

#
# Папка для ключей
mkdir -p /etc/apt/keyrings

#
# Добавим репозиторий Knot Resolver
curl -fsSL https://pkg.labs.nic.cz/gpg -o /etc/apt/keyrings/cznic-labs-pkg.gpg
echo "deb [signed-by=/etc/apt/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver $(lsb_release -cs) main" > /etc/apt/sources.list.d/cznic-labs-knot-resolver.list

#
# Ставим необходимые пакеты
apt-get update
apt-get install --reinstall -y git iptables knot-resolver idn sipcalc python3-pip diffutils socat lua-cqueues ipset
apt-get autoremove -y
apt-get clean

#
# Клонируем репозиторий и устанавливаем dnslib
rm -rf /tmp/dnslib
git clone https://github.com/paulc/dnslib.git /tmp/dnslib
PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install --force-reinstall --user /tmp/dnslib

#
# Клонируем репозиторий antizapret
rm -rf /tmp/antizapret
git clone https://github.com/UtyaVPN/AntiZapret-Core.git /tmp/antizapret

#
# Сохраняем пользовательские настройки и обработчики custom*.sh
cp /root/antizapret/config/*.txt /tmp/antizapret/setup/root/antizapret/config/ &>/dev/null || true
cp /root/antizapret/custom*.sh /tmp/antizapret/setup/root/antizapret/ &>/dev/null || true
cp /etc/knot-resolver/*.lua /tmp/antizapret/setup/etc/knot-resolver/ &>/dev/null || true

#
# Сохраняем настройки
echo "SETUP_DATE=$(date --iso-8601=seconds)
DEFAULT_INTERFACE=${DEFAULT_INTERFACE}
DEFAULT_IP=${DEFAULT_IP}
ANTIZAPRET_DNS=${ANTIZAPRET_DNS}
BLOCK_ADS=${BLOCK_ADS}
ALTERNATIVE_IP=${ALTERNATIVE_IP}
ROUTE_ALL=${ROUTE_ALL}
DISCORD_INCLUDE=${DISCORD_INCLUDE}
CLOUDFLARE_INCLUDE=${CLOUDFLARE_INCLUDE}
TELEGRAM_INCLUDE=${TELEGRAM_INCLUDE}
AMAZON_INCLUDE=${AMAZON_INCLUDE}
HETZNER_INCLUDE=${HETZNER_INCLUDE}
DIGITALOCEAN_INCLUDE=${DIGITALOCEAN_INCLUDE}
OVH_INCLUDE=${OVH_INCLUDE}
GOOGLE_INCLUDE=${GOOGLE_INCLUDE}
AKAMAI_INCLUDE=${AKAMAI_INCLUDE}
CLEAR_HOSTS=${CLEAR_HOSTS}" > /tmp/antizapret/setup/root/antizapret/setup

#
# Создаем папки для кэша Knot Resolver
mkdir -p /var/cache/knot-resolver
mkdir -p /var/cache/knot-resolver2
chown -R knot-resolver:knot-resolver /var/cache/knot-resolver
chown -R knot-resolver:knot-resolver /var/cache/knot-resolver2

#
# Выставляем разрешения
find /tmp/antizapret -type f -exec chmod 644 {} +
find /tmp/antizapret -type d -exec chmod 755 {} +
find /tmp/antizapret/setup/root/antizapret/ -type f -exec chmod +x {} +

# Копируем нужное, удаляем не нужное
find /tmp/antizapret -name '.gitkeep' -delete
rm -rf /root/antizapret
cp -r /tmp/antizapret/setup/* /
rm -rf /tmp/dnslib
rm -rf /tmp/antizapret

#
# Настраиваем DNS в AntiZapret-Core
if [[ "$ANTIZAPRET_DNS" == "2" ]]; then
	# Cloudflare+Quad9
	sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '195\.208\.4\.1', '195\.208\.5\.1'/'1.1.1.1', '1.0.0.1', '9.9.9.10', '149.112.112.10'/" /etc/knot-resolver/kresd.conf
elif [[ "$ANTIZAPRET_DNS" == "3" ]]; then
	# Comss
	sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '195\.208\.4\.1', '195\.208\.5\.1'/'83.220.169.155', '212.109.195.93'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'83.220.169.155', '212.109.195.93'/" /etc/knot-resolver/kresd.conf
elif [[ "$ANTIZAPRET_DNS" == "4" ]]; then
	# Xbox
	sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '195\.208\.4\.1', '195\.208\.5\.1'/'176.99.11.77', '80.78.247.254'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'176.99.11.77', '80.78.247.254'/" /etc/knot-resolver/kresd.conf
elif [[ "$ANTIZAPRET_DNS" == "5" ]]; then
	# Malw
	sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '195\.208\.4\.1', '195\.208\.5\.1'/'84.21.189.133', '64.188.98.242'/" /etc/knot-resolver/kresd.conf
	sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'84.21.189.133', '64.188.98.242'/" /etc/knot-resolver/kresd.conf
fi

#
# Используем альтернативные диапазоны ip-адресов
# 10.28.0.0/14 => 172.28.0.0/14
if [[ "$ALTERNATIVE_IP" == "y" ]]; then
	sed -i 's/10\./172\./g' /root/antizapret/proxy.py
	sed -i 's/10\./172\./g' /etc/knot-resolver/kresd.conf
fi

#
# Загружаем и создаем списки исключений IP-адресов
/root/antizapret/doall.sh ip

#
# Создадим файл подкачки размером 1 Гб если его нет
if [[ -z "$(swapon --show)" ]]; then
	set +e
	SWAPFILE="/swapfile"
	SWAPSIZE=1024
	dd if=/dev/zero of=$SWAPFILE bs=1M count=$SWAPSIZE
	chmod 600 "$SWAPFILE"
	mkswap "$SWAPFILE"
	swapon "$SWAPFILE"
	echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
fi

#
# Включим обновляемые службы
systemctl enable antizapret
systemctl enable antizapret-update
systemctl enable antizapret-update.timer
systemctl enable kresd@1
systemctl enable kresd@2
systemctl daemon-reload  
systemctl restart kresd@1 kresd@2
systemctl restart antizapret
#
# Если есть ошибки, выводим их
if [[ -n "$ERRORS" ]]; then
	echo -e "$ERRORS"
fi

#
# Перезагружаем
echo
echo -e '\e[1;32mAntiZapret-Core installed successfully!\e[0m'
echo 'Rebooting...'

reboot
