FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iputils-ping \
    iproute2 \
    net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install scapy for attack scripts
RUN pip install --no-cache-dir scapy>=2.5.0

WORKDIR /app

# Keep container alive — attacks are launched via docker exec
CMD ["sleep", "infinity"]
