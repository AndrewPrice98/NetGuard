# NetGuard in a container (Linux hosts).
#
#   docker build -t netguard .
#   docker run -d --name netguard --network host --cap-add NET_RAW --cap-add NET_ADMIN \
#       -v netguard-data:/data netguard
#
# --network host is required: NetGuard has to see your real LAN, its ARP table
# and its broadcast traffic, which a bridged container can't.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping iproute2 net-tools libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY netguard ./netguard
RUN pip install --no-cache-dir ".[sniff]"

# Data (database, config, vendor list) lives on a volume.
ENV HOME=/data
VOLUME /data
WORKDIR /data
EXPOSE 8000

# Inside the container 127.0.0.1 is still the host's loopback (host networking),
# so the dashboard stays local-only by default.
ENTRYPOINT ["netguard"]
CMD ["serve", "--sniff"]
