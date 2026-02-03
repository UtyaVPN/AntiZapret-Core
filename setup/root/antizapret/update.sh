#!/bin/bash
set -e

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

download_file() {
    local path="${1}"
    local tmp_path="${path}.tmp"
    local link="$2"
    if curl -sfL --connect-timeout 30 "$link" -o "$tmp_path"; then
        mv -f "$tmp_path" "$path"
    else
        echo "Trying connect via proxy..."
        if curl -sfL --connect-timeout 30 "$PROXY$link" -o "$tmp_path"; then
            mv -f "$tmp_path" "$path"
        else
            return 1
        fi
    fi
    return 0
}

rm -f download/*
mkdir -p temp/downloads

for source_file in config/sources/*.txt; do
    filename=$(basename "$source_file")
    dest="download/$filename"
    > "$dest"
    echo "Processing $filename sources..."
    
    # Download links from one source file in parallel
    while read -r link || [[ -n "$link" ]]; do
        [[ -z "$link" || "$link" == \#* ]] && continue
        (
            echo "  Downloading $link"
            safe_name=$(echo "$link" | md5sum | awk '{print $1}')
            tmp_download="temp/downloads/$safe_name"
            if download_file "$tmp_download" "$link"; then
                if [[ "$link" == *.gz ]]; then
                    gunzip -fc "$tmp_download" > "$tmp_download.unpacked" || true
                else
                    mv "$tmp_download" "$tmp_download.unpacked"
                fi
            else
                echo "  Failed to download $link"
            fi
        ) &
    done < "$source_file"
    wait

    # Combine results in order (optional, but keep it clean)
    cat temp/downloads/*.unpacked >> "$dest" 2>/dev/null || true
    rm -f temp/downloads/*.unpacked
done
rm -rf temp/downloads
exit 0
