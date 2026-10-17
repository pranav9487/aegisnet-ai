FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iputils-ping \
    iproute2 \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements_workload.txt ./
RUN pip install --no-cache-dir -r requirements_workload.txt

EXPOSE 8080

CMD ["python3", "/src/workload/server_app.py"]
