#!/bin/bash

###

set -e
shopt -s nullglob

# Обработка ошибок
handle_error() {
	echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

echo 'Parse AntiZapret-Core files:'

export LC_ALL=C

cd /root/antizapret

rm -f temp/*
rm -f result/*

source setup

# Гарантируем наличие новой строки в конце каждого файла в manual
for file in config/manual/*.txt; do
	sed -i -e '$a\' "$file"
done

if [[ -z "$1" || "$1" == "ip" || "$1" == "ips" || "$1" == "noclear" || "$1" == "noclean" ]]; then
	echo 'IPs...'

	# Собираем все IP из manual и download
	# Обрабатываем исключения
	sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' config/manual/exclude-ips.txt download/exclude-ips.txt | sort -u > temp/exclude-ips-all.txt
	# Разделяем на v4 и v6
	grep -v ':' temp/exclude-ips-all.txt > temp/exclude-ips.txt || true
	grep ':' temp/exclude-ips-all.txt > temp/exclude-ips-v6.txt || true

	# Обрабатываем включения
	sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' config/manual/include-ips.txt download/include-ips.txt | sort -u > temp/include-ips-all.txt
	# Разделяем на v4 и v6
	grep -v ':' temp/include-ips-all.txt > temp/include-ips.txt || true
	grep ':' temp/include-ips-all.txt > temp/include-ips-v6.txt || true

	# Убираем IPv4-адреса из исключений
	comm -13 temp/exclude-ips.txt temp/include-ips.txt > temp/route-ips-v4.txt || true

	# Валидация IPv4 CIDR
	awk -F'[/.]' 'NF==5 && $1>=0 && $1<=255 && $2>=0 && $2<=255 && $3>=0 && $3<=255 && $4>=0 && $4<=255 && $5>=1 && $5<=32 {print}' temp/route-ips-v4.txt > result/route-ips.txt || true

	# Выводим результат
	echo "$(wc -l < result/route-ips.txt) - route-ips.txt"

	# Убираем IPv6-адреса из исключений
	comm -13 temp/exclude-ips-v6.txt temp/include-ips-v6.txt > result/route-ips-v6.txt || true

	# Выводим результат
	echo "$(wc -l < result/route-ips-v6.txt) - route-ips-v6.txt"

	[[ "$ALTERNATIVE_IP" == "y" ]] && IP="${IP:-172}" || IP="10"
	[[ "$ALTERNATIVE_FAKE_IP" == "y" ]] && FAKE_IP="${FAKE_IP:-198.18}" || FAKE_IP="$IP.30"

	if [[ "$ATTACK_PROTECTION" == "y" ]]; then
		# Собираем разрешенные IP
		sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' config/manual/allow-ips.txt download/allow-ips.txt | sort -u > temp/allow-ips-all.txt
		
		# v4
		grep -v ':' temp/allow-ips-all.txt | awk -F'[/.]' 'NF==5 && $1>=0 && $1<=255 && $2>=0 && $2<=255 && $3>=0 && $3<=255 && $4>=0 && $4<=255 && $5>=1 && $5<=32 {print}' > result/allow-ips.txt || true
		echo "$(wc -l < result/allow-ips.txt) - allow-ips.txt"

		# Обновляем ipset antizapret-allow
		{
			echo 'create antizapret-allow hash:net -exist'
			echo 'flush antizapret-allow'
			while read -r cidr; do
				echo "add antizapret-allow $cidr -exist"
			done < result/allow-ips.txt
		} | ipset restore || true

		# v6
		grep ':' temp/allow-ips-all.txt > result/allow-ips-v6.txt || true
		echo "$(wc -l < result/allow-ips-v6.txt) - allow-ips-v6.txt"

		# Обновляем ipset antizapret-allow-v6
		{
			echo 'create antizapret-allow-v6 hash:net family inet6 -exist'
			echo 'flush antizapret-allow-v6'
			while read -r cidr; do
				echo "add antizapret-allow-v6 $cidr -exist"
			done < result/allow-ips-v6.txt
		} | ipset restore || true
	fi
fi

if [[ -z "$1" || "$1" == "host" || "$1" == "hosts" || "$1" == "noclear" || "$1" == "noclean" ]]; then
	echo 'Hosts...'

	# Обрабатываем список с рекламными доменами для блокировки
	# Поддерживаем и обычные списки, и формат AdGuard
	sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d; s/[]_~:/?#\[@!$&'\''()*+,;=].*//; s/.*/\L&/' download/include-adblock-hosts.txt config/manual/include-adblock-hosts.txt > temp/include-adblock-hosts-raw.txt
	# Добавляем обработку формата AdGuard для тех же файлов
	sed -n '/\*/!s/^||\(.*\)\^.*$/\1/p' download/include-adblock-hosts.txt config/manual/include-adblock-hosts.txt | sed -E 's/.*/\L&/; /^[0-9.]+$/d' >> temp/include-adblock-hosts-raw.txt

	# Обрабатываем список с исключениями из блокировки рекламы
	sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d; s/[]_~:/?#\[@!$&'\''()*+,;=].*//; s/.*/\L&/' download/exclude-adblock-hosts.txt config/manual/exclude-adblock-hosts.txt > temp/exclude-adblock-hosts-raw.txt
	# Добавляем обработку формата AdGuard исключений
	sed -n '/\*/!s/^@@||\(.*\)\^.*$/\1/p' download/exclude-adblock-hosts.txt config/manual/exclude-adblock-hosts.txt | sed -E 's/.*/\L&/; /^[0-9.]+$/d' >> temp/exclude-adblock-hosts-raw.txt

	# Строгая очистка и Punycode для рекламных списков
	sed -n 's/^[[:punct:]]\+//; s/[[:punct:]]\+$//; /\./{s/.*/\L&/; /^[а-яa-z0-9.-]\+$/p}' temp/include-adblock-hosts-raw.txt \
	| CHARSET=UTF-8 idn --no-tld 2>/dev/null > temp/include-adblock-hosts.txt || cat temp/include-adblock-hosts-raw.txt > temp/include-adblock-hosts.txt

	sed -n 's/^[[:punct:]]\+//; s/[[:punct:]]\+$//; /\./{s/.*/\L&/; /^[а-яa-z0-9.-]\+$/p}' temp/exclude-adblock-hosts-raw.txt \
	| CHARSET=UTF-8 idn --no-tld 2>/dev/null > temp/exclude-adblock-hosts.txt || cat temp/exclude-adblock-hosts-raw.txt > temp/exclude-adblock-hosts.txt

	# Удаляем дубли и сортируем
	sort -u temp/include-adblock-hosts.txt > result/include-adblock-hosts.txt
	sort -u temp/exclude-adblock-hosts.txt > result/exclude-adblock-hosts.txt

	echo "$(wc -l < result/include-adblock-hosts.txt) - include-adblock-hosts.txt"
	echo "$(wc -l < result/exclude-adblock-hosts.txt) - exclude-adblock-hosts.txt"

	# RPZ для рекламы
	echo -e '$TTL 10800\n@ SOA . . (1 1 1 1 10800)' > result/deny.rpz
	echo -e '$TTL 10800\n@ SOA . . (1 1 1 1 10800)' > result/deny2.rpz
	sed 's/$/ CNAME ./; p; s/^/*./' result/include-adblock-hosts.txt >> result/deny.rpz
	sed 's/$/ CNAME rpz-passthru./; p; s/^/*./' result/exclude-adblock-hosts.txt >> result/deny.rpz
	
	# Добавляем пользовательские RPZ
	sed 's/\r//g; /^;/d; /^$/d' download/rpz.txt config/manual/rpz.txt >> result/deny.rpz
	sed 's/\r//g; /^;/d; /^$/d' download/rpz2.txt config/manual/rpz2.txt >> result/deny2.rpz

	# Обновляем файлы в /etc/knot-resolver/
	for f in deny.rpz deny2.rpz; do
		if [[ -f result/$f ]] && ! diff -q result/$f /etc/knot-resolver/$f >/dev/null 2>&1; then
			cp -f result/$f /etc/knot-resolver/$f.tmp
			mv -f /etc/knot-resolver/$f.tmp /etc/knot-resolver/$f
		fi
	done

	# Обрабатываем основные списки хостов
	sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d; s/[]_~:/?#\[@!$&'\''()*+,;=].*//; s/.*/\L&/' download/include-hosts.txt config/manual/include-hosts.txt > temp/include-hosts.txt
	sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d; s/[]_~:/?#\[@!$&'\''()*+,;=].*//; s/.*/\L&/' download/exclude-hosts.txt config/manual/exclude-hosts.txt | sort -u > temp/exclude-hosts.txt
	sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d; s/[]_~:/?#\[@!$&'\''()*+,;=].*//; s/.*/\L&/' download/remove-hosts.txt config/manual/remove-hosts.txt | sort -u > temp/remove-hosts.txt

	# Добавляем доменную базу (например, от antifilter) с конвертацией в Punycode
	mv temp/include-hosts.txt temp/include-hosts-raw.txt
	sed -n 's/^[[:punct:]]\+//; s/[[:punct:]]\+$//; /\./{s/.*/\L&/; /^[а-яa-z0-9.-]\+$/p}' temp/include-hosts-raw.txt \
	| CHARSET=UTF-8 idn --no-tld 2>/dev/null > temp/include-hosts.txt || cat temp/include-hosts-raw.txt > temp/include-hosts.txt
	
	# Удаляем казино, если включено
	if [[ "$CLEAR_HOSTS" == "y" ]]; then
		grep -Evi '[ck]a+[szc3]+[iley1]+n+[0-9o]|[vw][uy]+[l1]+[kc]a+n|[vw]a+[vw]+a+d+a|x-*bet|most-*bet|leon-*bet|rio-*bet|mel-*bet|ramen-*bet|marathon-*bet|max-*bet|bet-*win|gg-*bet|spin-*bet|banzai-*bet|1iks-*bet|x-*slot|sloto-*zal|max-*slot|bk-*leon|gold-*fishka|play-*fortuna|dragon-*money|poker-*dom|1-*win|crypto-*bos|free-*spin|fair-*spin|no-*deposit|igrovye|avtomaty|bookmaker|zerkalo|official|slottica|sykaaa|admiral-*x|x-*admiral|pinup-*bet|pari-*match|betting|partypoker|jackpot|bonus|azino[0-9-]|888-*starz|zooma[0-9-]|zenit-*bet|eldorado|slots|vodka|newretro|platinum|igrat|flagman|arkada' temp/include-hosts.txt | sort -u > temp/include-hosts2.txt
	else
		sort -u temp/include-hosts.txt > temp/include-hosts2.txt
	fi

	# Удаляем из remove-hosts и исключений
	comm -13 temp/remove-hosts.txt temp/include-hosts2.txt > temp/include-hosts3.txt
	comm -13 temp/remove-hosts.txt temp/exclude-hosts.txt > result/exclude-hosts.txt

	# Оптимизация поддоменов (удаление избыточных)
	sed -E '/\..*\./ s/^([0-9]*www[0-9]*|hd[0-9]*|[A-Za-z]|[0-9]+)\.//' temp/include-hosts3.txt result/exclude-hosts.txt > temp/include-hosts4.txt
	rev temp/include-hosts4.txt | \
	sort -t '.' -k1,1 -k2,2 -k3,3 -k4,4 -k5,5 -k6,6 -k7,7 -k8,8 -k9,9 -k10,10 -k11,11 -k12,12 -k13,13 -k14,14 -k15,15 -k16,16 -k17,17 -k18,18 -k19,19 -k20,20 | \
	awk 'BEGIN { last = "" }
	{
		if (last != "" && index($0, last ".") == 1) {
			next
		}
		last = $0
		print $0
	}' | rev | sort -u > temp/include-hosts5.txt

	# Итоговый список
	comm -23 temp/include-hosts5.txt result/exclude-hosts.txt > result/include-hosts.txt

	echo "$(wc -l < result/include-hosts.txt) - include-hosts.txt"
	echo "$(wc -l < result/exclude-hosts.txt) - exclude-hosts.txt"

	# Proxy RPZ
	echo -e '$TTL 10800\n@ SOA . . (1 1 1 1 10800)' > result/proxy.rpz
	sed '/^\.$/ s/.*/*. CNAME ./; t; s/$/ CNAME ./; p; s/^/*./' result/include-hosts.txt >> result/proxy.rpz
	sed '/^\.$/ s/.*/*. CNAME rpz-passthru./; t; s/$/ CNAME rpz-passthru./; p; s/^/*./' result/exclude-hosts.txt >> result/proxy.rpz

	if [[ -f result/proxy.rpz ]] && ! diff -q result/proxy.rpz /etc/knot-resolver/proxy.rpz >/dev/null 2>&1; then
		cp -f result/proxy.rpz /etc/knot-resolver/proxy.rpz.tmp
		mv -f /etc/knot-resolver/proxy.rpz.tmp /etc/knot-resolver/proxy.rpz
		sleep 5
		if [[ "$1" != "noclear" && "$1" != "noclean" ]]; then
			# Очищаем кэш Knot Resolver
			count="$(echo 'cache.clear()' | socat - /run/knot-resolver/control/1 | grep -oE '[0-9]+' || echo 0)"
			echo "DNS cache cleared: $count entries"
		fi
	fi
fi

exit 0
