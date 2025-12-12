# vwarp Unified Configuration Guide

This guide covers the complete configuration system for vwarp, including all connection options, obfuscation settings, and advanced features.

## 📄 Configuration Files

### Quick Start
```bash
# Create your config from the complete example
cp config/examples/complete-config.json my-config.json
# Edit my-config.json with your settings
vwarp --config my-config.json

# Or use CLI presets for quick testing
vwarp --masque --noize-preset moderate
vwarp --gool --noize-preset heavy
```

## 🔧 Complete Configuration Reference

### 1. Basic Connection Settings
```json
{
  "version": "1.0",                     // Config format version
  "bind": "127.0.0.1:8086",            // SOCKS5 proxy listen address  
  "endpoint": "162.159.192.1:2408",     // Cloudflare WARP endpoint
  "key": "your-warp-license-key-here",  // Your WARP+ license key (optional)
  "dns": "1.1.1.1",                    // DNS server for name resolution
  "test_url": "https://cp.cloudflare.com/", // URL for connectivity tests
  "proxy": "socks5://127.0.0.1:1080"   // Upstream SOCKS5 proxy (optional)
}
```

### 2. Connection Modes

#### Standard WireGuard Mode
```bash
vwarp --config my-config.json  # Uses WireGuard by default
```

#### MASQUE Mode  
```bash
vwarp --config my-config.json --masque
```

#### Warp-in-Warp (Gool) Mode
```bash
vwarp --config my-config.json --gool
```

### 3. WireGuard Configuration
```json
{
  "wireguard": {
    "enabled": true,                    // Enable/disable WireGuard mode
    "config": "/path/to/wg.conf",      // Path to existing WG config (optional)
    "reserved": "1,2,3",               // Reserved bytes (decimal format: 1,2,3)
    "fwmark": 0,                       // Firewall mark for routing (Linux only)
    "atomicnoize": {
      // Signature Packets (in CPS format)
      "I1": "<b 0c0d0e0f>",           // Initial signature packet
      "I2": "<b 0xc700...>",          // Large signature packet (truncated)
      "I3": "<b 040506>",             // Medium signature packet  
      "I4": "<b 0708>",               // Small signature packet
      "I5": "<b 09>",                 // Minimal signature packet
      
      // Timing Configuration  
      "S1": 1,                        // Stage 1 timing multiplier
      "S2": 2,                        // Stage 2 timing multiplier
      
      // Junk Packet Configuration
      "Jc": 85,                       // Total junk packets to send
      "Jmin": 40,                     // Minimum junk packet size (bytes)
      "Jmax": 90,                     // Maximum junk packet size (bytes)
      "JcAfterI1": 3,                 // Junk packets after I1
      "JcBeforeHS": 5,                // Junk packets before handshake  
      "JcAfterHS": 4,                 // Junk packets after handshake
      
      // Advanced Timing
      "JunkInterval": 150000000,      // Delay between junk packets (150ms)
      "HandshakeDelay": 25000000,     // Delay before handshake (25ms)
      "AllowZeroSize": true           // Allow zero-size packets
    }
  }
}
```

### 4. MASQUE Configuration
```json
{
  "masque": {
    "enabled": true,                    // Enable/disable MASQUE mode
    "preferred": false,                 // Prefer over WireGuard when both enabled
    "config": {
      // Signature Packets (MASQUE noize format)
      "i1": "<b 0d0a0d0a>",           // HTTP-like signature
      "i2": "<b 0xc700...>",          // Large signature (same as WG I2)
      "i3": "<b 0102>",               // Simple signature
      "i4": "<b 030405>",             // Medium signature
      "i5": "<b 060708>",             // Complex signature
      
      // Fragmentation Settings
      "fragment_size": 512,           // Fragment size in bytes
      "fragment_initial": true,       // Fragment Initial packets
      "FragmentDelay": 5000000,       // Delay between fragments (5ms)
      
      // Padding Configuration  
      "PaddingMin": 16,               // Minimum padding bytes
      "PaddingMax": 64,               // Maximum padding bytes
      "RandomPadding": true,          // Use random padding
      
      // Junk Packet Configuration
      "Jc": 15,                       // Total junk packets (lighter than WG)
      "Jmin": 30,                     // Minimum junk size
      "Jmax": 120,                    // Maximum junk size
      "JcBeforeHS": 3,                // Junk before handshake
      "JcAfterI1": 2,                 // Junk after first signature
      "JcDuringHS": 5,                // Junk during handshake
      
      // Protocol Mimicry
      "MimicProtocol": "https",       // Mimic protocol (https/http/quic)  
      "SNIFragmentation": true,       // Fragment SNI in TLS ClientHello
      "MimicTLS": true,               // Add TLS-like headers
      "CustomHeaders": true           // Add custom HTTP headers
    }
  }
}
```

### 5. Additional Options
```json
{
  "psiphon": {
    "enabled": false,                   // Enable Psiphon integration
    "country": "US"                     // Country code for exit node
  },
  "metadata": {
    "name": "Production Config",        // Human-readable name
    "description": "Production setup with heavy obfuscation",
    "author": "admin",                  // Config author
    "created_at": "2025-01-01T00:00:00Z" // Creation timestamp
  }
}
```

## 🚀 Usage Examples

### Basic Usage
```bash
# Use config file for all settings
vwarp --config my-config.json

# Override connection mode with flags
vwarp --config my-config.json --masque    # Force MASQUE mode
vwarp --config my-config.json --gool      # Force Gool mode

# Combine config with CLI presets
vwarp --config my-config.json --noize-preset heavy
```

### Quick CLI Presets (No Config File)
```bash
# Light obfuscation (fast)
vwarp --masque --noize-preset light

# Moderate obfuscation (balanced)  
vwarp --gool --noize-preset moderate

# Heavy obfuscation (strong)
vwarp --masque --noize-preset heavy
```

## 📝 Configuration Tips & Best Practices

### 🎯 Obfuscation Levels

**Light (Fast Performance)**
```json
{
  "wireguard": { "atomicnoize": { "Jc": 10, "JunkInterval": 50000000 } },
  "masque": { "config": { "Jc": 5, "MimicProtocol": "quic" } }
}
```

**Moderate (Balanced)**  
```json
{
  "wireguard": { "atomicnoize": { "Jc": 50, "JunkInterval": 100000000 } },
  "masque": { "config": { "Jc": 15, "MimicProtocol": "https", "fragment_initial": true } }
}
```

**Heavy (Maximum Stealth)**
```json
{
  "wireguard": { "atomicnoize": { "Jc": 100, "JunkInterval": 200000000 } },
  "masque": { "config": { "Jc": 30, "MimicProtocol": "https", "SNIFragmentation": true } }
}
```

### ⚙️ Field Format Reference

| Field Type | Format | Example | Description |
|------------|--------|---------|-------------|
| **Signature Packets** | CPS format | `"<b 0c0d0e0f>"` | Custom Packet Specification with hex bytes |
| **Reserved Bytes** | Decimal CSV | `"1,2,3"` | Comma-separated decimal values (NOT hex) |
| **Timing** | Nanoseconds | `150000000` | All delays in nanoseconds (150ms = 150000000) |
| **Size Limits** | Bytes | `512` | Packet/fragment sizes in bytes |
| **Addresses** | Standard | `"127.0.0.1:8086"` | IP:port format |

### ⚠️ Common Issues & Solutions

**1. Reserved Bytes Format Error**
```
❌ "reserved": "0x01,0x02,0x03"  # Hex format causes parsing error
✅ "reserved": "1,2,3"           # Use decimal format
```

**2. Missing Key for Gool Mode**  

do not place the key if  you want  the core handle the registration itself. use youre key only if you have a professional paid account on cloudflare
```json
✅ "key": "your-warp-license-key-here"  // Required for --gool mode
```

**3. Config File vs CLI Flags**
- Config file settings are applied first
- CLI flags (--masque, --gool) override connection mode
- CLI --noize-preset overrides obfuscation settings

### 🔄 Protocol Selection Logic

1. **CLI Flag Priority**: `--masque` or `--gool` override config file mode
2. **Config File**: `masque.preferred: true` prefers MASQUE over WireGuard  
3. **Fallback**: WireGuard is default if both protocols are enabled

### 📊 Performance Impact

| Obfuscation Level | Latency Impact | Bandwidth Overhead | Detection Resistance |
|-------------------|----------------|-------------------|---------------------|
| **None** | +0ms | +0% | Low |
| **Light** | +10-20ms | +5-10% | Medium |  
| **Moderate** | +20-50ms | +10-20% | High |
| **Heavy** | +50-100ms | +20-40% | Maximum |

### 🔗 Related Documentation

- [Complete Obfuscation Guide](../../docs/VWARP_OBFUSCATION_GUIDE.md) - Detailed noize configuration
- [SOCKS Proxy Guide](../../docs/SOCKS_PROXY_GUIDE.md) - Proxy chaining setup
- [GitHub Repository](https://github.com/bepass-org/vwarp) - Latest updates and issues

## 🏢 Production Deployment

### 🚀 Deployment Checklist

**1. Configuration Validation**
```bash
# Test your config file
vwarp --config production.json --verbose

# Validate connectivity
vwarp --config production.json --masque --scan
```

**2. Service Setup (Linux)**
```bash
# Create systemd service
sudo tee /etc/systemd/system/vwarp.service << EOF
[Unit]
Description=vwarp VPN Service
After=network.target

[Service]
Type=simple
User=vwarp
WorkingDirectory=/opt/vwarp
ExecStart=/opt/vwarp/vwarp --config /opt/vwarp/production.json --masque
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl enable vwarp
sudo systemctl start vwarp
```

**3. Docker Deployment**
```dockerfile
FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY vwarp /usr/local/bin/
COPY production.json /etc/vwarp/
EXPOSE 8086
CMD ["vwarp", "--config", "/etc/vwarp/production.json", "--masque"]
```

### 📈 Monitoring & Logging

**Health Check Script**
```bash
#!/bin/bash
# health-check.sh
curl -x socks5://127.0.0.1:8086 -s https://cp.cloudflare.com/ > /dev/null
if [ $? -eq 0 ]; then
  echo "vwarp: HEALTHY"
  exit 0
else
  echo "vwarp: UNHEALTHY - restarting service"
  systemctl restart vwarp
  exit 1
fi
```

**Log Analysis**
```bash
# Monitor real-time logs
journalctl -u vwarp -f

# Check connection stats
grep "MASQUE connection established" /var/log/vwarp.log

# Monitor obfuscation effectiveness
grep "noize" /var/log/vwarp.log | tail -20
```

## ⚡ Performance Tuning

### Network Optimization
```json
{
  "masque": {
    "config": {
      "fragment_size": 1200,     // Optimize for your MTU
      "Jc": 10,                  // Lower for better performance
      "FragmentDelay": 2000000,  // Reduce delay for speed
      "PaddingMin": 8,          // Minimal padding for performance
      "PaddingMax": 16
    }
  }
}
```

### Memory & CPU Optimization
- **Light Load**: `Jc: 5-10`, disable fragmentation
- **Medium Load**: `Jc: 10-20`, enable basic fragmentation  
- **Heavy Load**: `Jc: 20-50`, full obfuscation features

## 🔧 Troubleshooting

### Common Issues & Solutions

**1. Reserved Bytes Parse Error**
```
❌ "reserved": "0x01,0x02,0x03"  # Causes parse error
✅ "reserved": "1,2,3"           # Correct format
```

**2. Config File Not Loading**
```bash
# Check file permissions
ls -la my-config.json

# Validate JSON syntax
jq . my-config.json

# Test with minimal config
echo '{}' > minimal.json
vwarp --config minimal.json --masque
```

**3. Connection Timeouts**
```json
// Increase timeouts for slow networks
{
  "masque": {
    "config": {
      "Jc": 5,                    // Reduce junk packets
      "FragmentDelay": 10000000,  // Increase delay
      "PaddingMin": 0,           // Disable padding
      "MimicProtocol": "quic"     // Use faster protocol
    }
  }
}
```

**4. High CPU Usage**
```bash
# Use lighter obfuscation
vwarp --config production.json --noize-preset light

# Monitor resource usage
top -p $(pgrep vwarp)
```

**5. DNS Resolution Issues**
```json
{
  "dns": "8.8.8.8",              // Try different DNS
  "test_url": "https://1.1.1.1/" // Use IP-based test
}
```

### Debug Commands
```bash
# Enable verbose logging
vwarp --config production.json --verbose

# Test specific endpoint
vwarp --endpoint 162.159.192.1:2408 --masque --verbose

# Scan for optimal endpoints
vwarp --scan --rtt 500ms

# Export current config
vwarp --noize-export moderate:debug-config.json
```

## 📚 Advanced Tips

- **Development**: Use `light` preset for faster testing
- **Production**: Use `moderate` or `heavy` based on network conditions  
- **Debugging**: Enable verbose mode with `--verbose` flag
- **Chaining**: Use `proxy` field to route through multiple SOCKS5 proxies
- **Scanning**: Built-in endpoint scanner finds optimal Cloudflare IPs
- **Monitoring**: Implement health checks and log monitoring
- **Scaling**: Use Docker/K8s for container deployment