# vwarp Obfuscation Configuration Examples

This directory contains production-ready configuration files for different censorship scenarios and network conditions.

## 📁 Available Configurations

### `basic-obfuscation.json`
- **Use case**: Most firewalls and basic DPI detection systems
- **Performance**: Low overhead (~10-20ms latency, ~5-10% bandwidth)
- **Features**: 
  - Light MASQUE noize (Jc: 10)
  - Basic protocol mimicry
  - Minimal padding and fragmentation
- **Recommended for**: Corporate networks, basic censorship

### `moderate-obfuscation.json`  
- **Use case**: Corporate firewalls and moderate DPI systems
- **Performance**: Medium overhead (~30-50ms latency, ~10-20% bandwidth)
- **Features**: 
  - Balanced MASQUE + WireGuard obfuscation
  - Protocol fragmentation enabled
  - Moderate junk packet injection
- **Recommended for**: Government networks, ISP-level filtering

### `heavy-obfuscation.json`
- **Use case**: Strict censorship and advanced DPI systems
- **Performance**: High overhead (~50-100ms latency, ~20-40% bandwidth)  
- **Features**: 
  - Maximum obfuscation (Jc: 50+)
  - Full protocol mimicry and fragmentation
  - Heavy randomization and padding
- **Recommended for**: China GFW, Iran, strict authoritarian networks

## 🚀 Quick Usage

### Basic Setup
```bash
# Light obfuscation for most scenarios
vwarp --config docs/examples/basic-obfuscation.json --masque

# Moderate obfuscation for corporate firewalls
vwarp --config docs/examples/moderate-obfuscation.json --masque

# Heavy obfuscation for strict censorship
vwarp --config docs/examples/heavy-obfuscation.json --masque
```

### Advanced Usage
```bash
# Use with proxy chaining for double-VPN
vwarp --config docs/examples/heavy-obfuscation.json --proxy socks5://127.0.0.1:1080

# Override connection mode while keeping obfuscation settings
vwarp --config docs/examples/moderate-obfuscation.json --gool

# Enable verbose logging for debugging
vwarp --config docs/examples/basic-obfuscation.json --masque --verbose
```

## ⚙️ Configuration Comparison

| Feature | Basic | Moderate | Heavy |
|---------|-------|----------|--------|
| **MASQUE Junk Packets** | 5-10 | 15-25 | 30-50 |
| **WireGuard Junk Packets** | 10-20 | 25-50 | 50-100 |
| **Protocol Mimicry** | QUIC | HTTPS | HTTPS |
| **Fragmentation** | Disabled | Basic | Full |
| **SNI Fragmentation** | No | Yes | Yes |
| **Random Padding** | Minimal | Medium | Maximum |
| **Timing Randomization** | Basic | Medium | Complex |
| **Memory Usage** | ~50MB | ~100MB | ~200MB |
| **CPU Usage** | Low | Medium | High |

## 🌍 Regional Recommendations

### Asia-Pacific
```bash
# China (Great Firewall)
vwarp --config docs/examples/heavy-obfuscation.json --masque

# Iran 
vwarp --config docs/examples/heavy-obfuscation.json --gool

# Corporate networks (Singapore, Japan)
vwarp --config docs/examples/moderate-obfuscation.json --masque
```

### Europe & Americas
```bash
# Corporate environments
vwarp --config docs/examples/basic-obfuscation.json --masque

# Government networks
vwarp --config docs/examples/moderate-obfuscation.json --masque
```

### Testing & Development
```bash
# Local testing (minimal overhead)
vwarp --masque --noize-preset light

# Performance testing
vwarp --config docs/examples/basic-obfuscation.json --verbose
```

## 🔧 Customization Guide

### Creating Custom Configs
```bash
# Start with a base configuration
cp docs/examples/moderate-obfuscation.json my-custom.json

# Adjust for your network (example: reduce junk packets for speed)
jq '.masque.config.Jc = 8' my-custom.json > temp.json && mv temp.json my-custom.json
jq '.wireguard.atomicnoize.Jc = 15' my-custom.json > temp.json && mv temp.json my-custom.json

# Test your custom configuration
vwarp --config my-custom.json --masque --verbose
```

### Performance Tuning
```json
// For faster connections (reduce obfuscation)
{
  "masque": {
    "config": {
      "Jc": 5,                    // Fewer junk packets
      "FragmentDelay": 1000000,   // Faster fragmentation
      "MimicProtocol": "quic"     // Lighter protocol mimicry
    }
  }
}

// For maximum stealth (increase obfuscation)
{
  "masque": {
    "config": {
      "Jc": 50,                   // More junk packets
      "FragmentDelay": 10000000,  // Slower, more realistic
      "SNIFragmentation": true,   // Fragment TLS handshake
      "MimicProtocol": "https"    // Full HTTPS mimicry
    }
  }
}
```

## 📊 Performance Benchmarks

### Latency Impact (Approximate)
- **No obfuscation**: +0ms baseline
- **Basic**: +10-20ms (light junk injection)
- **Moderate**: +30-50ms (fragmentation + medium junk)
- **Heavy**: +50-100ms (full obfuscation + timing delays)

### Bandwidth Overhead
- **Basic**: 5-10% (minimal padding and junk)
- **Moderate**: 10-20% (fragmentation overhead)
- **Heavy**: 20-40% (maximum padding and junk packets)

### Detection Resistance
- **Basic**: Effective against simple DPI systems
- **Moderate**: Bypasses most corporate firewalls  
- **Heavy**: Designed for advanced state-level censorship

## ⚠️ Important Notes

1. **Performance vs Security**: Higher obfuscation = lower performance
2. **Network Conditions**: Adjust based on your specific network environment
3. **Regular Updates**: Keep configurations updated with latest techniques
4. **Testing**: Always test in your environment before production use

## 🔗 Related Documentation

- **[Complete Configuration Guide](../../config/examples/README.md)** - Detailed setup instructions
- **[Production Deployment](../PRODUCTION_DEPLOYMENT.md)** - Production setup and monitoring
- **[Obfuscation Guide](../VWARP_OBFUSCATION_GUIDE.md)** - Technical details on obfuscation methods
- **[Troubleshooting](../../config/examples/README.md#troubleshooting)** - Common issues and solutions
```

## Customization

Copy any example file and modify parameters as needed. See the [Complete Obfuscation Guide](../VWARP_OBFUSCATION_GUIDE.md) for detailed parameter explanations and configuration options.