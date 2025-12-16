# vwarp Configuration Guide & Examples

This comprehensive guide covers the complete configuration system for vwarp, including all connection options, obfuscation settings, and ready-to-use example configurations. as the noize configuration with options  was tricy and frustraing and also we were adding warp and masque to this repo, we decided to make a unified configuration file for  almost any variable the the vwarp can use . we ade this config a complete unti cencorship and adaptable in all situations. follow the instructions below to get the  best out of it. 

## 📄 Quick Start

### 🌟 Recommended for Everyone (All Countries)
the best approach that we encourge you to do is to use ocnfig files and also share for youre friends to elp them conenct easier.
```bash
# Use the universal working configuration (recommended first choice)
vwarp --config docs/examples/sample-working.json --masque

# Copy and customize for your needs
cp docs/examples/sample-working.json my-config.json
# Edit my-config.json with your settings
vwarp --config my-config.json --masque
```

### Alternative Quick Options

another option is to use the harkcoded presets in code. they are working for now specially the light one . 
```bash
# CLI presets (no config file needed)
vwarp --masque --noize-preset moderate

# Use complete template for custom setups
cp docs/examples/sample-working.json my-config.json
vwarp --config my-config.json --masque
```

## 📁 Available Example Configurations

### 🌟 `sample-working.json` (RECOMMENDED FIRST CHOICE)
- **Use case**: Universal configuration - works in all countries and network conditions
- **Performance**: Optimized balance (~15-30ms latency, ~8-15% bandwidth)
- **Features**: 
  - Tested and proven configuration
  - Balanced MASQUE + WireGuard settings
  - Works in China, Iran, Russia, and other restrictive countries
  - Corporate network friendly
- **Recommended for**: 🌍 **ALL COUNTRIES - Start here first!**

the other options is availbe but we  are sure they may not work on some protocols and some netwroks . the best is take sample and  change it based on youre network 

### `basic-obfuscation.json`
- **Use case**: Light filtering and basic DPI detection systems
- **Performance**: Low overhead (~10-20ms latency, ~5-10% bandwidth)
- **Features**: Minimal MASQUE noize (Jc: 5-10), basic protocol mimicry
- **Recommended for**: Corporate networks, light censorship

### `moderate-obfuscation.json`  
- **Use case**: Corporate firewalls and moderate DPI systems
- **Performance**: Medium overhead (~30-50ms latency, ~10-20% bandwidth)
- **Features**: Enhanced MASQUE + WireGuard obfuscation, fragmentation enabled
- **Recommended for**: Government networks, ISP-level filtering

### `heavy-obfuscation.json`
- **Use case**: Extreme censorship scenarios (fallback if sample-working fails)
- **Performance**: High overhead (~50-100ms latency, ~20-40% bandwidth)  
- **Features**: Maximum obfuscation (Jc: 50+), full protocol mimicry
- **Recommended for**: Last resort for strictest networks

### Configuration Templates
Use any of the above configurations as templates for creating custom configurations. The `sample-working.json` serves as the best starting point for most use cases.

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

### 2. WireGuard Configuration
```json
{
  "wireguard": {
    "enabled": true,                    // Enable/disable WireGuard mode
    "config": "/path/to/wg.conf",      // Path to existing WG config (optional)
    "reserved": "1,2,3",               // Reserved bytes (decimal format)
    "fwmark": 0,                       // Firewall mark for routing (Linux only)
    "atomicnoize": {
      // Signature Packets (in CPS format)
      "I1": "<b 0c0d0e0f>",           // Initial signature packet
      "I2": "<b 0xc700...>",          // Large signature packet
      "I3": "<b 040506>",             // Medium signature packet  
      "I4": "<b 0708>",               // Small signature packet
      "I5": "<b 09>",                 // Minimal signature packet
      
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

### 3. MASQUE Configuration
```json
{
  "masque": {
    "enabled": true,                    // Enable/disable MASQUE mode
    "preferred": false,                 // Prefer over WireGuard when both enabled
    "config": {
      // Signature Packets (MASQUE noize format)
      "i1": "<b 0d0a0d0a>",           // HTTP-like signature
      "i2": "<b 0xc700...>",          // Large signature
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
      "Jc": 15,                       // Total junk packets
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

### 4. Additional Options
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

#### Psiphon Country Codes
**Americas**: US, CA, BR  
**Europe**: GB, DE, FR, IT, ES, NL, SE, NO, DK, FI, CH, AT, BE, IE, PT, PL, CZ, HU, RO, BG, HR, EE, LV, SK, RS  
**Asia-Pacific**: JP, SG, AU, IN  

you can finid what countriy each one is by following the appropiate readme :
https://www.iso.org/obp/ui/#search

## 🚀 Usage Examples

### 🌟 Recommended First Try (All Countries)
```bash
# Start with the universal working configuration
vwarp --config docs/examples/sample-working.json --masque

# Copy and customize for your needs
cp docs/examples/sample-working.json my-config.json
vwarp --config my-config.json --masque
```

### Alternative Configurations
```bash
# If sample-working doesn't work, try these in order:
vwarp --config docs/examples/basic-obfuscation.json --masque
vwarp --config docs/examples/moderate-obfuscation.json --masque
vwarp --config docs/examples/heavy-obfuscation.json --masque

# CLI presets (no config file needed)
vwarp --masque --noize-preset moderate

# Use with proxy chaining for maximum privacy
vwarp --config docs/examples/sample-working.json --proxy socks5://127.0.0.1:1080
```



### 🌟 Universal First Choice
- **ALL COUNTRIES**: Start with `sample-working.json` - tested worldwide


## 🔧 Customization

To customize configurations:
1. Copy an example config: `cp docs/examples/moderate-obfuscation.json my-custom.json`
2. Edit the `Jc` values (lower = faster, higher = more stealth)
3. Test: `vwarp --config my-custom.json --masque --verbose`

For detailed configuration options, see this complete Configuration Guide.

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

## ⚙️ Field Format Reference

| Field Type | Format | Example | Description |
|------------|--------|---------|-------------|
| **Signature Packets** | CPS format | `"<b 0c0d0e0f>"` | Custom Packet Specification with hex bytes |
| **Reserved Bytes** | Decimal CSV | `"1,2,3"` | Comma-separated decimal values (NOT hex) |
| **Timing** | Nanoseconds | `150000000` | All delays in nanoseconds (150ms = 150000000) |
| **Size Limits** | Bytes | `512` | Packet/fragment sizes in bytes |
| **Addresses** | Standard | `"127.0.0.1:8086"` | IP:port format |

## 🚑 Troubleshooting

### Common Issues & Solutions

**1. Reserved Bytes Format Error**
```
❌ "reserved": "0x01,0x02,0x03"  # Hex format causes parsing error
✅ "reserved": "1,2,3"           # Use decimal format
```

**2. Missing Key for Gool Mode**  
Do not place the key if you want the core to handle registration itself. Use your key only if you have a professional paid Cloudflare account.
```json
 "key": "your-warp-license-key-here"  
```

**3. Config File vs CLI Flags**
- Config file settings are applied first
- CLI flags (--masque, --gool) override connection mode
- CLI --noize-preset overrides obfuscation settings

**4. Connection Timeouts**
```bash
# First try the universal working config
vwarp --config docs/examples/sample-working.json --masque

# If still timing out, reduce obfuscation
vwarp --config docs/examples/basic-obfuscation.json --masque
```

**5. Config Not Working in Your Country**
```bash
# Step 1: Always try sample-working first
vwarp --config docs/examples/sample-working.json --masque --verbose

# Step 2: If fails, escalate obfuscation
vwarp --config docs/examples/moderate-obfuscation.json --masque
vwarp --config docs/examples/heavy-obfuscation.json --masque

# Step 3: Add proxy chaining for maximum stealth
vwarp --config docs/examples/sample-working.json --proxy socks5://127.0.0.1:1080
```

## 🎯 Configuration Tips & Best Practices

### Protocol Selection Logic
1. **CLI Flag Priority**: `--masque` or `--gool` override config file mode
2. **Config File**: `masque.preferred: true` prefers MASQUE over WireGuard  
3. **Fallback**: WireGuard is default if both protocols are enabled

### Performance vs Security Trade-offs

| Obfuscation Level | Latency Impact | Bandwidth Overhead | Detection Resistance |
|-------------------|----------------|-------------------|---------------------|
| **None** | +0ms | +0% | Low |
| **Light** | +10-20ms | +5-10% | Medium |  
| **Moderate** | +20-50ms | +10-20% | High |
| **Heavy** | +50-100ms | +20-40% | Maximum |

### Customization Guide

1. **Copy a base config**: `cp docs/examples/moderate-obfuscation.json my-custom.json`
2. **Adjust Jc values**: Lower = faster, Higher = more stealth
3. **Test thoroughly**: `vwarp --config my-custom.json --masque --verbose`
4. **Monitor performance**: Check latency and bandwidth usage

## ⚠️ Important Notes

1. **Performance vs Security**: Higher obfuscation = lower performance
2. **Network Conditions**: Adjust based on your specific network environment
3. **Regular Updates**: Keep configurations updated with latest techniques
4. **Testing**: Always test in your environment before production use
5. **Format Accuracy**: Use decimal format for reserved bytes, nanoseconds for timing

## 🔗 Related Documentation

- **[Production Deployment](../PRODUCTION_DEPLOYMENT.md)** - Enterprise deployment and monitoring
- **[Complete Obfuscation Guide](../VWARP_OBFUSCATION_GUIDE.md)** - Technical details on obfuscation methods
- **[SOCKS5 Proxy Guide](../SOCKS_PROXY_GUIDE.md)** - Double-VPN proxy chaining
- **[Troubleshooting](#troubleshooting)** - Common issues and solutions
```

## Customization

Copy any example file and modify parameters as needed. See the [Complete Obfuscation Guide](../VWARP_OBFUSCATION_GUIDE.md) for detailed parameter explanations and configuration options.
