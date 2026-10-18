FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iputils-ping \
    iproute2 \
    ebtables \
    arptables \
    iptables \
    net-tools \
    tcpdump \
    procps \
    curl \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Phase 1: lightweight sensor + enforcer deps (needed for v0.1) ─────────────
# Heavy ML packages (chromadb, sentence-transformers, langgraph, torch) are
# installed separately in later versions to keep the initial build fast.
RUN pip install --no-cache-dir \
    scapy>=2.5.0 \
    pyroute2>=0.7.12 \
    pyshark>=0.6.0 \
    networkx>=3.2.1 \
    pydantic>=2.7.0 \
    jsonschema>=4.22.0 \
    python-dotenv>=1.0.1 \
    requests>=2.31.0 \
    pytest>=8.2.0 \
    pytest-asyncio>=0.23.0

# ── Phase 2: heavy ML deps (needed for v0.5+) ─────────────────────────────────
# Uncomment when building for v0.5 memory layer:
# COPY requirements.txt ./
# RUN pip install --no-cache-dir -r requirements.txt

# Keep container alive — sensor and enforcer launched via docker exec
CMD ["sleep", "infinity"]
