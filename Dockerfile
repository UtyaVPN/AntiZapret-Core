FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C \
    PATH="/root/.local/bin:$PATH"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl gpg iptables gawk idn sipcalc python3-pip diffutils \
    socat lua-cqueues ipset lsb-release ca-certificates cron kmod \
    iproute2 procps && \
    curl -fsSL https://pkg.labs.nic.cz/gpg -o /etc/apt/keyrings/cznic-labs-pkg.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver $(lsb_release -cs) main" > /etc/apt/sources.list.d/cznic-labs-knot-resolver.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends knot-resolver && \
    PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install --no-cache-dir dnslib py-radix && \
    apt-get purge -y gpg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

FROM base

COPY setup/etc/knot-resolver /etc/knot-resolver/
COPY setup/etc/sysctl.d /etc/sysctl.d/
COPY setup/root/antizapret /root/antizapret/
COPY setup/usr/lib/knot-resolver/kres_modules /usr/lib/knot-resolver/kres_modules/
COPY entrypoint.sh /entrypoint.sh

RUN cp -r /root/antizapret/config /root/antizapret/config_default && \
    cp /etc/knot-resolver/kresd.conf /etc/knot-resolver/kresd.conf.bak && \
    cp /root/antizapret/proxy.py /root/antizapret/proxy.py.bak && \
    mkdir -p /var/cache/knot-resolver /var/cache/knot-resolver2 && \
    chown -R knot-resolver:knot-resolver /var/cache/knot-resolver /var/cache/knot-resolver2 && \
    echo '0 3 * * * root echo "Scheduled update started..." > /proc/1/fd/1 && sleep $(shuf -i 0-3599 -n 1) && /root/antizapret/doall.sh noclear > /proc/1/fd/1 2>&1' > /etc/cron.d/antizapret-update && \
    chmod 0644 /etc/cron.d/antizapret-update && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
