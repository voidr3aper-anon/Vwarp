# vwarp Production Deployment Guide

This guide covers production deployment, monitoring, and maintenance of vwarp in various environments.

## 📦 Installation

### Binary Installation
```bash
# Download latest release
wget https://github.com/voidr3aper-anon/Vwarp/releases/latest/download/vwarp-linux
chmod +x vwarp-linux
sudo mv vwarp-linux /usr/local/bin/vwarp

# Verify installation
vwarp version
```

### Build from Source
```bash
git clone https://github.com/voidr3aper-anon/Vwarp.git
cd vwarp
go build -o vwarp cmd/vwarp/*.go
```

## 🏗️ Production Setup

### 1. System Configuration

**Create dedicated user**
```bash
sudo useradd --system --shell /bin/false --home-dir /opt/vwarp vwarp
sudo mkdir -p /opt/vwarp/{config,logs}
sudo chown -R vwarp:vwarp /opt/vwarp
```

**Configure firewall**
```bash
# Allow SOCKS5 proxy port
sudo ufw allow 8086/tcp

# Allow outbound WARP endpoints
sudo ufw allow out 2408/udp
sudo ufw allow out 443/udp
```

### 2. Configuration Management

**Production config template**
```json
{
  "version": "1.0",
  "bind": "0.0.0.0:8086",
  "endpoint": "162.159.192.1:2408",
  "key": "${WARP_LICENSE_KEY}",
  "dns": "1.1.1.1",
  "test_url": "https://cp.cloudflare.com/",
  "masque": {
    "enabled": true,
    "preferred": true,
    "config": {
      "Jc": 15,
      "MimicProtocol": "https",
      "fragment_initial": true,
      "RandomPadding": true,
      "PaddingMin": 16,
      "PaddingMax": 32
    }
  },
  "wireguard": {
    "enabled": true,
    "reserved": "1,2,3",
    "atomicnoize": {
      "Jc": 25,
      "JunkInterval": 100000000,
      "HandshakeDelay": 50000000
    }
  },
  "metadata": {
    "name": "Production vwarp",
    "description": "Production deployment with balanced obfuscation",
    "environment": "production"
  }
}
```

**Environment-based configs**
```bash
# Create environment-specific configs
cp /opt/vwarp/config/production.json /opt/vwarp/config/staging.json
cp /opt/vwarp/config/production.json /opt/vwarp/config/development.json

# Edit for different environments
nano /opt/vwarp/config/staging.json    # Lower Jc values for testing
nano /opt/vwarp/config/development.json # Minimal obfuscation
```

### 3. Service Management

**Systemd service**
```bash
sudo tee /etc/systemd/system/vwarp.service << 'EOF'
[Unit]
Description=vwarp VPN Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=vwarp
Group=vwarp
WorkingDirectory=/opt/vwarp
ExecStart=/usr/local/bin/vwarp --config /opt/vwarp/config/production.json --masque --verbose
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/vwarp
PrivateTmp=yes

# Resource limits
LimitNOFILE=1048576
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable vwarp
sudo systemctl start vwarp
```

**Service management commands**
```bash
# Check status
sudo systemctl status vwarp

# View logs
sudo journalctl -u vwarp -f

# Restart service
sudo systemctl restart vwarp

# Reload configuration
sudo systemctl reload vwarp
```

## 🐳 Docker Deployment

### Dockerfile
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o vwarp cmd/vwarp/*.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /app/vwarp ./
COPY config/ ./config/

# Create non-root user
RUN adduser -D -s /bin/sh vwarp
USER vwarp

EXPOSE 8086

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD wget --quiet --tries=1 --spider --proxy=on --proxy-user= --proxy-password= http_proxy=socks5://localhost:8086 https://cp.cloudflare.com/ || exit 1

CMD ["./vwarp", "--config", "./config/production.json", "--masque"]
```

### Docker Compose
```yaml
version: '3.8'

services:
  vwarp:
    build: .
    container_name: vwarp
    restart: unless-stopped
    ports:
      - "8086:8086"
    environment:
      - WARP_LICENSE_KEY=${WARP_LICENSE_KEY}
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "--proxy=on", "http_proxy=socks5://localhost:8086", "https://cp.cloudflare.com/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vwarp
  namespace: vwarp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: vwarp
  template:
    metadata:
      labels:
        app: vwarp
    spec:
      containers:
      - name: vwarp
        image: vwarp:latest
        ports:
        - containerPort: 8086
        env:
        - name: WARP_LICENSE_KEY
          valueFrom:
            secretKeyRef:
              name: vwarp-secret
              key: license-key
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - "wget --quiet --tries=1 --spider --proxy=on http_proxy=socks5://localhost:8086 https://cp.cloudflare.com/"
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - "wget --quiet --tries=1 --spider --proxy=on http_proxy=socks5://localhost:8086 https://cp.cloudflare.com/"
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: vwarp-config

---
apiVersion: v1
kind: Service
metadata:
  name: vwarp-service
  namespace: vwarp
spec:
  selector:
    app: vwarp
  ports:
  - port: 8086
    targetPort: 8086
  type: LoadBalancer
```

## 📊 Monitoring & Observability

### 1. Health Monitoring

**Health check script**
```bash
#!/bin/bash
# /opt/vwarp/scripts/health-check.sh

PROXY="socks5://127.0.0.1:8086"
TEST_URL="https://cp.cloudflare.com/"
TIMEOUT=10

# Test SOCKS5 connectivity
if curl -x "$PROXY" --connect-timeout "$TIMEOUT" -s "$TEST_URL" > /dev/null; then
    echo "$(date): vwarp HEALTHY - SOCKS5 proxy responding"
    exit 0
else
    echo "$(date): vwarp UNHEALTHY - SOCKS5 proxy failed"
    exit 1
fi
```

**Monitoring with Prometheus**
```yaml
# vwarp-exporter.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'vwarp'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: /metrics
    scrape_interval: 30s
```

### 2. Log Management

**Structured logging**
```bash
# Configure log rotation
sudo tee /etc/logrotate.d/vwarp << 'EOF'
/opt/vwarp/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 vwarp vwarp
    postrotate
        systemctl reload vwarp
    endscript
}
EOF
```

**Log analysis**
```bash
# Monitor connection patterns
tail -f /var/log/syslog | grep vwarp

# Check obfuscation effectiveness
journalctl -u vwarp | grep -E "(noize|obfus|junk)"

# Monitor performance
journalctl -u vwarp | grep -E "(latency|rtt|timeout)"
```

### 3. Alerting

**Basic alerting script**
```bash
#!/bin/bash
# /opt/vwarp/scripts/alert.sh

WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
SERVICE="vwarp"

if ! systemctl is-active --quiet "$SERVICE"; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚨 $SERVICE service is down on $(hostname)\"}" \
        "$WEBHOOK_URL"
fi

# Check if SOCKS5 proxy is responding
if ! /opt/vwarp/scripts/health-check.sh; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"⚠️ $SERVICE proxy not responding on $(hostname)\"}" \
        "$WEBHOOK_URL"
fi
```

## 🔧 Maintenance

### 1. Updates
```bash
# Backup current config
cp /opt/vwarp/config/production.json /opt/vwarp/config/production.json.bak.$(date +%Y%m%d)

# Download new version
wget https://github.com/voidr3aper-anon/Vwarp/releases/latest/download/vwarp-linux -O /tmp/vwarp-new

# Test new version
/tmp/vwarp-new --config /opt/vwarp/config/production.json --masque &
sleep 10
kill %1

# If test passed, replace
sudo systemctl stop vwarp
sudo mv /tmp/vwarp-new /usr/local/bin/vwarp
sudo chmod +x /usr/local/bin/vwarp
sudo systemctl start vwarp
```

### 2. Configuration Management
```bash
# Validate config before applying
jq empty /opt/vwarp/config/production.json

# Test configuration
vwarp --config /opt/vwarp/config/production.json --masque --verbose &
TEST_PID=$!
sleep 5
kill $TEST_PID

# Apply if test passed
sudo systemctl reload vwarp
```

### 3. Performance Optimization
```bash
# Monitor resource usage
top -p $(pgrep vwarp)
ss -tuln | grep 8086

# Network tuning
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p
```

## 🚨 Troubleshooting

### Common Issues

**1. Service won't start**
```bash
# Check configuration
vwarp --config /opt/vwarp/config/production.json --masque --verbose

# Check permissions
ls -la /opt/vwarp/config/
sudo chown vwarp:vwarp /opt/vwarp/config/production.json

# Check logs
journalctl -u vwarp -n 50
```

**2. High resource usage**
```bash
# Reduce obfuscation
jq '.masque.config.Jc = 5' /opt/vwarp/config/production.json > /tmp/config.json
mv /tmp/config.json /opt/vwarp/config/production.json

# Monitor improvement
systemctl restart vwarp
```

**3. Connection timeouts**
```bash
# Test endpoint connectivity
nc -u -v 162.159.192.1 2408

# Try different endpoint
vwarp --scan --rtt 500ms
```

## 📈 Scaling

### Load Balancing
```nginx
upstream vwarp_backend {
    server 127.0.0.1:8086;
    server 127.0.0.1:8087;
    server 127.0.0.1:8088;
}

server {
    listen 8080;
    location / {
        proxy_pass http://vwarp_backend;
    }
}
```

### Multi-Instance Setup
```bash
# Create multiple configs
for i in {1..3}; do
    port=$((8085 + i))
    jq ".bind = \"127.0.0.1:$port\"" production.json > production-$i.json
done

# Create service instances
for i in {1..3}; do
    sudo cp vwarp.service vwarp@$i.service
    sudo sed -i "s/production.json/production-$i.json/" vwarp@$i.service
    sudo systemctl enable vwarp@$i
    sudo systemctl start vwarp@$i
done
```

## 🔐 Security Considerations

### Network Security
- Use firewall rules to restrict access
- Consider VPN-only access to management interfaces
- Implement rate limiting for SOCKS5 proxy
- Monitor for unusual traffic patterns

### Configuration Security
- Store sensitive keys in environment variables or secrets management
- Use read-only configuration mounts in containers
- Implement configuration validation
- Regular security audits of configuration

### Operational Security
- Regular updates and patches
- Monitoring for security events
- Backup and recovery procedures
- Incident response planning

---

**Need Help?** Check the [Configuration Guide](CONFIG_FORGE.md) and [Troubleshooting Section](CONFIG_FORGE.md#troubleshooting) for more details.