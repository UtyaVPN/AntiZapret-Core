#!/bin/bash
set -e

# Обработка ошибок
handle_error() {
	echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

echo 'Update AntiZapret-Core files:'

cd /root/antizapret

export LC_ALL=C

mkdir -p temp download result

PROXY="https://api.codetabs.com/v1/proxy?quest="

function download_file {
	local path="${1}"
	local tmp_path="${path}.tmp"
	local link="$2"
	if curl -fL --connect-timeout 30 "$link" -o "$tmp_path"; then
		mv -f "$tmp_path" "$path"
	else
		echo "Trying connect via proxy..."
		if curl -fL --connect-timeout 30 "$PROXY$link" -o "$tmp_path"; then
			mv -f "$tmp_path" "$path"
		else
			return 1
		fi
	fi
	return 0
}

rm -f download/*

# Скачиваем из источников
for source_file in config/sources/*.txt; do
	filename=$(basename "$source_file")
	dest="download/$filename"
	> "$dest"
	
	echo "Processing $filename sources..."
	while read -r link || [[ -n "$link" ]]; do
		[[ -z "$link" || "$link" == \#* ]] && continue
		echo "  Downloading $link"
		tmp_download="temp/dl.tmp"
		if download_file "$tmp_download" "$link"; then
			if [[ "$link" == *.gz ]]; then
				gunzip -fc "$tmp_download" >> "$dest" || true
			else
				cat "$tmp_download" >> "$dest"
				echo "" >> "$dest"
			fi
			rm -f "$tmp_download"
		else
			echo "  Failed to download $link"
		fi
	done < "$source_file"
done

exit 0
