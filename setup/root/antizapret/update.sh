#!/bin/bash
set -e

# Обработка ошибок
handle_error() {
	echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

if [[ -n "$1" && "$1" != "ip" && "$1" != "ips" && "$1" != "host" && "$1" != "hosts" && "$1" != "noclear" && "$1" != "noclean" ]]; then
	echo "Ignored invalid parameter: $1"
	set -- ""
fi

echo 'Update AntiZapret-Core files:'

cd /root/antizapret

export LC_ALL=C

rm -f download/*

# URLs and Paths
UPDATE_LINK="https://raw.githubusercontent.com/UtyaVPN/AntiZapret-Core/main/setup/root/antizapret/update.sh"
UPDATE_PATH="update.sh"

PARSE_LINK="https://raw.githubusercontent.com/UtyaVPN/AntiZapret-Core/main/setup/root/antizapret/parse.sh"
PARSE_PATH="parse.sh"

DOALL_LINK="https://raw.githubusercontent.com/UtyaVPN/AntiZapret-Core/main/setup/root/antizapret/doall.sh"
DOALL_PATH="doall.sh"

DOMAIN_LINK="https://antifilter.download/list/domains.lst"
DOMAIN_PATH="download/domain.txt"

DOMAIN2_LINK="https://community.antifilter.download/list/domains.lst"
DOMAIN2_PATH="download/domain-2.txt"

#DUMP_LINK="https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv.gz"
#DUMP_PATH="download/dump.csv.gz"
DUMP_LINK="https://svn.code.sf.net/p/zapret-info/code/dump.csv"
DUMP_PATH="download/dump.csv"

#NXDOMAIN_LINK="https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt"
NXDOMAIN_LINK="https://svn.code.sf.net/p/zapret-info/code/nxdomain.txt"
NXDOMAIN_PATH="download/nxdomain.txt"

RPZ_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/rpz.txt"
RPZ_PATH="download/rpz.txt"

RPZ2_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/rpz2.txt"
RPZ2_PATH="download/rpz2.txt"

INCLUDE_HOSTS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/include-hosts.txt"
INCLUDE_HOSTS_PATH="download/include-hosts.txt"

EXCLUDE_HOSTS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/exclude-hosts.txt"
EXCLUDE_HOSTS_PATH="download/exclude-hosts.txt"

INCLUDE_ADBLOCK_HOSTS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/include-adblock-hosts.txt"
INCLUDE_ADBLOCK_HOSTS_PATH="download/include-adblock-hosts.txt"

EXCLUDE_ADBLOCK_HOSTS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/exclude-adblock-hosts.txt"
EXCLUDE_ADBLOCK_HOSTS_PATH="download/exclude-adblock-hosts.txt"

ADGUARD_LINK="https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
ADGUARD_PATH="download/adguard.txt"

OISD_LINK="https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_small.txt"
OISD_PATH="download/oisd.txt"

DISCORD_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/discord-ips.txt"
DISCORD_IPS_PATH="download/discord-ips.txt"

CLOUDFLARE_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/cloudflare-ips.txt"
CLOUDFLARE_IPS_PATH="download/cloudflare-ips.txt"

AMAZON_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/amazon-ips.txt"
AMAZON_IPS_PATH="download/amazon-ips.txt"

HETZNER_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/hetzner-ips.txt"
HETZNER_IPS_PATH="download/hetzner-ips.txt"

DIGITALOCEAN_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/digitalocean-ips.txt"
DIGITALOCEAN_IPS_PATH="download/digitalocean-ips.txt"

OVH_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/ovh-ips.txt"
OVH_IPS_PATH="download/ovh-ips.txt"

TELEGRAM_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/telegram-ips.txt"
TELEGRAM_IPS_PATH="download/telegram-ips.txt"

GOOGLE_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/google-ips.txt"
GOOGLE_IPS_PATH="download/google-ips.txt"

AKAMAI_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/akamai-ips.txt"
AKAMAI_IPS_PATH="download/akamai-ips.txt"

WHATSAPP_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/whatsapp-ips.txt"
WHATSAPP_IPS_PATH="download/whatsapp-ips.txt"

ROBLOX_IPS_LINK="https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup/root/antizapret/download/roblox-ips.txt"
ROBLOX_IPS_PATH="download/roblox-ips.txt"

function download {
	local path="${1}"
	local tmp_path="${path}.tmp"
	local link="$2"
	echo "Downloading $path..."
	
	# Retry up to 3 times
	for i in {1..3}; do
		if curl -fL --connect-timeout 10 --max-time 60 "$link" -o "$tmp_path"; then
			mv -f "$tmp_path" "$path"
			if [[ "$path" == *.sh ]]; then
				chmod +x "$path"
			elif [[ "$path" == *.gz ]]; then
				gunzip -f "$path" || > "${path%.gz}"
			fi
			return 0
		else
			echo "Failed to download $path (Attempt $i/3)"
			sleep 2
		fi
	done
	
	echo "Error: Failed to download $path after 3 attempts."
	return 1
}

# Core scripts (sequential)
download $UPDATE_PATH $UPDATE_LINK
download $PARSE_PATH $PARSE_LINK
download $DOALL_PATH $DOALL_LINK

source setup

# Parallel downloads
pids=""

if [[ -z "$1" || "$1" == "host" || "$1" == "hosts" || "$1" == "noclear" || "$1" == "noclean" ]]; then
	download "$DOMAIN_PATH" "$DOMAIN_LINK" & pids="$pids $!"
	download "$DOMAIN2_PATH" "$DOMAIN2_LINK" & pids="$pids $!"
	( download $DUMP_PATH $DUMP_LINK || > "$DUMP_PATH" ) & pids="$pids $!"
	( download $NXDOMAIN_PATH $NXDOMAIN_LINK || > "$NXDOMAIN_PATH" ) & pids="$pids $!"
	download $RPZ_PATH $RPZ_LINK & pids="$pids $!"
	download $RPZ2_PATH $RPZ2_LINK & pids="$pids $!"
	download $INCLUDE_HOSTS_PATH $INCLUDE_HOSTS_LINK & pids="$pids $!"

	if [[ "$ROUTE_ALL" = "y" ]]; then
		download $EXCLUDE_HOSTS_PATH $EXCLUDE_HOSTS_LINK & pids="$pids $!"
	else
		printf '# НЕ РЕДАКТИРУЙТЕ ЭТОТ ФАЙЛ!' > $EXCLUDE_HOSTS_PATH
	fi

	if [[ "$BLOCK_ADS" = "y" ]]; then
		download $INCLUDE_ADBLOCK_HOSTS_PATH $INCLUDE_ADBLOCK_HOSTS_LINK & pids="$pids $!"
		download $EXCLUDE_ADBLOCK_HOSTS_PATH $EXCLUDE_ADBLOCK_HOSTS_LINK & pids="$pids $!"
		download $ADGUARD_PATH $ADGUARD_LINK & pids="$pids $!"
		download $OISD_PATH $OISD_LINK & pids="$pids $!"
	else
		> $INCLUDE_ADBLOCK_HOSTS_PATH
		> $EXCLUDE_ADBLOCK_HOSTS_PATH
		> $ADGUARD_PATH
		> $OISD_PATH
	fi
fi

if [[ -z "$1" || "$1" == "ip" || "$1" == "ips" || "$1" == "noclear" || "$1" == "noclean" ]]; then
	[[ "$DISCORD_INCLUDE" = "y" ]] && { download $DISCORD_IPS_PATH $DISCORD_IPS_LINK & pids="$pids $!"; }
	[[ "$CLOUDFLARE_INCLUDE" = "y" ]] && { download $CLOUDFLARE_IPS_PATH $CLOUDFLARE_IPS_LINK & pids="$pids $!"; }
	[[ "$AMAZON_INCLUDE" = "y" ]] && { download $AMAZON_IPS_PATH $AMAZON_IPS_LINK & pids="$pids $!"; }
	[[ "$HETZNER_INCLUDE" = "y" ]] && { download $HETZNER_IPS_PATH $HETZNER_IPS_LINK & pids="$pids $!"; }
	[[ "$DIGITALOCEAN_INCLUDE" = "y" ]] && { download $DIGITALOCEAN_IPS_PATH $DIGITALOCEAN_IPS_LINK & pids="$pids $!"; }
	[[ "$OVH_INCLUDE" = "y" ]] && { download $OVH_IPS_PATH $OVH_IPS_LINK & pids="$pids $!"; }
	[[ "$TELEGRAM_INCLUDE" = "y" ]] && { download $TELEGRAM_IPS_PATH $TELEGRAM_IPS_LINK & pids="$pids $!"; }
	[[ "$GOOGLE_INCLUDE" = "y" ]] && { download $GOOGLE_IPS_PATH $GOOGLE_IPS_LINK & pids="$pids $!"; }
	[[ "$AKAMAI_INCLUDE" = "y" ]] && { download $AKAMAI_IPS_PATH $AKAMAI_IPS_LINK & pids="$pids $!"; }
	[[ "$WHATSAPP_INCLUDE" = "y" ]] && { download $WHATSAPP_IPS_PATH $WHATSAPP_IPS_LINK & pids="$pids $!"; }
	[[ "$ROBLOX_INCLUDE" = "y" ]] && { download $ROBLOX_IPS_PATH $ROBLOX_IPS_LINK & pids="$pids $!"; }
fi

# Wait for all downloads to finish
for pid in $pids; do
	wait $pid || { echo "Background job $pid failed"; exit 1; }
done

exit 0
