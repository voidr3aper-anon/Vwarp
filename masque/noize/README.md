# MASQUE Noize - Advanced QUIC Obfuscation Protocol

Comprehensive packet obfuscation system for MASQUE/QUIC connections, designed to bypass Deep Packet Inspection (DPI) and firewall restrictions like the Great Firewall of China (GFW).

## Features

### 🔒 Core Obfuscation Techniques

1. **QUIC Packet Fragmentation**
   - Splits QUIC Initial packets into smaller fragments
   - Configurable fragment sizes (e.g., 128, 256, 512 bytes)
   - Delayed fragment transmission to evade pattern detection

2. **Protocol Mimicry**
   - DNS: Disguise packets as DNS queries
   - HTTPS/HTTP3: Mimic TLS/HTTPS traffic
   - DTLS: Appear as DTLS encrypted datagrams
   - STUN: Look like STUN protocol packets

3. **Signature Packet Injection**
   - I1-I5: Customizable protocol signature packets
   - CPS (Custom Protocol Signature) format support
   - Dynamic timestamps and nonces

4. **Junk Packet Generation**
   - Send decoy packets before/during/after handshake
   - Configurable size ranges and timing
   - Protocol-aware junk packets

5. **Padding & Timing Obfuscation**
   - Random padding to mask packet sizes
   - Randomized delays between packets
   - Natural traffic simulation

### 🚀 Preset Configurations

#### 1. Light Obfuscation (`-noize-preset light`)
- **Overhead**: ~5-10%
- **Latency**: +5-15ms
- **Use Case**: Fast connection with basic obfuscation
```
Padding: 8-16 bytes
Junk Packets: 2 (32-64 bytes)
Fragment: Disabled
Delay: 5ms
```

#### 2. Medium Obfuscation (`-noize-preset medium`) *DEFAULT*
- **Overhead**: ~15-25%
- **Latency**: +10-30ms
- **Use Case**: Balanced performance and obfuscation
```
Padding: 16-64 bytes
Junk Packets: 5 (64-256 bytes)
Fragment: 512 bytes
Delay: 10ms
Protocol: HTTP/3
```

#### 3. Heavy Obfuscation (`-noize-preset heavy`)
- **Overhead**: ~30-50%
- **Latency**: +20-50ms
- **Use Case**: Maximum obfuscation, high stealth
```
Padding: 32-128 bytes
Junk Packets: 10 (128-512 bytes)
Fragment: 256 bytes
Delay: 20ms (randomized)
Protocol: DTLS
SNI Fragmentation: Enabled
```

#### 4. Stealth Mode (`-noize-preset stealth`)
- **Overhead**: ~20-35%
- **Latency**: +15-40ms
- **Use Case**: Looks like legitimate HTTPS traffic
```
Mimic: HTTPS (TLS ClientHello patterns)
Padding: 16-48 bytes
Junk Packets: 3 (40-200 bytes)
Timing: Realistic delays (5-25ms)
```

#### 5. GFW Bypass Mode (`-noize-preset gfw`)
- **Overhead**: ~35-60%
- **Latency**: +25-60ms
- **Use Case**: Specifically designed for Great Firewall bypass
```
Padding: 48-192 bytes (aggressive)
Junk Packets: 8 (64-384 bytes)
Fragment: 128 bytes (heavy fragmentation)
Protocol: DTLS
SNI Fragmentation: 8 bytes
Timing: Randomized (1-20ms)
Fake Packet Loss: 2%
```

## Usage

### Command Line

#### Basic Connection with Obfuscation
```bash
# Enable default (medium) obfuscation
masque-test.exe -noize -endpoint 162.159.198.1:443

# Use specific preset
masque-test.exe -noize -noize-preset gfw -endpoint 162.159.198.1:443

# Custom configuration
masque-test.exe -noize \
  -noize-fragment 256 \
  -noize-junk 10 \
  -noize-mimic dtls \
  -endpoint 162.159.198.1:443
```

#### Scanner with Obfuscation
```bash
# Scan with GFW bypass mode
masque-test.exe -scan \
  -noize -noize-preset gfw \
  -range4 "162.159.192.0/24,162.159.198.0/24"

# Light obfuscation for fast scanning
masque-test.exe -scan \
  -noize -noize-preset light \
  -scan-workers 20 -scan-max 50
```

### Programmatic API

#### Go Code Example
```go
package main

import (
    "context"
    "github.com/bepass-org/vwarp/masque"
    "github.com/bepass-org/vwarp/masque/noize"
)

func main() {
    ctx := context.Background()
    
    // Create noize configuration
    noizeConfig := noize.GFWBypassConfig()
    
    // Customize if needed
    noizeConfig.FragmentSize = 128
    noizeConfig.Jc = 10
    noizeConfig.MimicProtocol = "dtls"
    
    // Create MASQUE client with noize
    client, err := masque.AutoLoadOrRegisterWithOptions(ctx, masque.AutoRegisterOptions{
        DeviceName:  "my-device",
        Endpoint:    "162.159.198.1:443",
        NoizeConfig: noizeConfig,
        EnableNoize: true,
    })
    
    if err != nil {
        panic(err)
    }
    defer client.Close()
    
    // Use client...
}
```

#### Custom Configuration
```go
// Create fully custom noize config
customConfig := &noize.NoizeConfig{
    // Signature packets (CPS format)
    I1: "<b 0d0a0d0a><t><r 32>",  // CRLF + timestamp + 32 random bytes
    I2: "<r 64>",                  // 64 random bytes
    
    // Fragmentation
    FragmentSize:    256,
    FragmentInitial: true,
    FragmentDelay:   2 * time.Millisecond,
    
    // Padding
    PaddingMin: 32,
    PaddingMax: 96,
    RandomPadding: true,
    
    // Junk packets
    Jc:           8,
    Jmin:         64,
    Jmax:         384,
    JcBeforeHS:   3,
    JcAfterI1:    2,
    JcDuringHS:   2,
    JcAfterHS:    1,
    JunkInterval: 5 * time.Millisecond,
    JunkRandom:   true,
    
    // Protocol mimicry
    MimicProtocol: "dtls",
    
    // Timing
    HandshakeDelay: 25 * time.Millisecond,
    RandomDelay:    true,
    DelayMin:       2 * time.Millisecond,
    DelayMax:       20 * time.Millisecond,
    
    // Advanced
    SNIFragmentation: true,
    SNIFragment:      8,
    UseTimestamp:     true,
    UseNonce:         true,
    RandomizeInitial: true,
}
```

## CPS (Custom Protocol Signature) Format

The noize system uses a powerful CPS format for creating custom packet signatures:

### CPS Tags

| Tag | Description | Example |
|-----|-------------|---------|
| `<b hex>` | Static bytes (hex) | `<b 0d0a>` = CRLF |
| `<t>` | 32-bit timestamp | `<t>` = current Unix time |
| `<c>` | 32-bit counter | `<c>` = incremental counter |
| `<r N>` | N random bytes | `<r 16>` = 16 random bytes |
| `<n>` | 64-bit nonce | `<n>` = nanosecond timestamp |
| `<x K>` | XOR with key K | `<x 42>` = XOR all previous bytes with 42 |

### CPS Examples

```
# HTTP-like signature
I1: "<b 474554202f20485454502f312e31><r 16>"
# Result: "GET / HTTP/1.1" + 16 random bytes

# TLS ClientHello start
I1: "<b 160301><r 2><b 0100>"
# Result: TLS record header + random + handshake header

# DNS-like with timestamp
I1: "<b 0001><t><r 8>"
# Result: DNS flags + timestamp + random query ID

# Timestamped signature
I1: "<b 0d0a0d0a><t><n><r 32>"
# Result: CRLF + timestamp + nonce + random data
```

## Technical Details

### QUIC Packet Types Detected
- **Initial**: First client packet, heavily obfuscated
- **Handshake**: Handshake continuation
- **0-RTT**: Early data packets
- **1-RTT**: Regular encrypted data
- **Retry**: Server retry packets

### Obfuscation Sequence

```
1. Pre-Handshake Phase:
   - Send I1 signature packet
   - Send JcAfterI1 junk packets (2ms intervals)
   - Send JcBeforeHS junk packets
   - Send I2-I5 signature packets (1ms intervals)
   - Wait HandshakeDelay

2. Handshake Phase:
   - Fragment Initial packet if configured
   - Add random padding (PaddingMin-PaddingMax)
   - Wrap in protocol header (DNS/HTTPS/DTLS/STUN)
   - Send JcDuringHS junk packets concurrently
   - Apply random delays

3. Post-Handshake Phase:
   - Send JcAfterHS junk packets
   - Continue padding on data packets
   - Maintain timing obfuscation
```

### Performance Impact

| Preset | Bandwidth Overhead | Latency Added | CPU Usage |
|--------|-------------------|---------------|-----------|
| None | 0% | 0ms | Baseline |
| Light | 5-10% | 5-15ms | +2-5% |
| Medium | 15-25% | 10-30ms | +5-10% |
| Heavy | 30-50% | 20-50ms | +10-20% |
| Stealth | 20-35% | 15-40ms | +7-15% |
| GFW | 35-60% | 25-60ms | +12-25% |

## Bypass Techniques

### 1. Fragmentation Bypass
- GFW can't reassemble fragments properly
- Breaks pattern matching across fragments
- Effective against static signatures

### 2. Timing Randomization
- Statistical traffic analysis defeated
- No consistent inter-packet timing
- Natural traffic simulation

### 3. Protocol Mimicry
- Packets look like legitimate protocols
- DNS: Appears as DNS queries/responses
- HTTPS: Mimics TLS handshakes
- DTLS: Looks like encrypted VPN traffic

### 4. SNI Fragmentation
- Breaks SNI-based blocking
- Splits Server Name Indication across packets
- Defeats SNI inspection

### 5. Junk Traffic
- Obscures real traffic patterns
- Creates noise in statistical analysis
- Variable timing confuses DPI

## Troubleshooting

### Connection Fails with Noize
```bash
# Try lighter obfuscation
masque-test.exe -noize -noize-preset light -endpoint IP:PORT

# Disable fragmentation
masque-test.exe -noize -noize-fragment 0 -endpoint IP:PORT

# Test without noize
masque-test.exe -endpoint IP:PORT
```

### High Latency
```bash
# Reduce junk packets
masque-test.exe -noize -noize-junk 2 -endpoint IP:PORT

# Use light preset
masque-test.exe -noize -noize-preset light -endpoint IP:PORT
```

### Still Blocked by GFW
```bash
# Maximum obfuscation
masque-test.exe -noize -noize-preset gfw -endpoint IP:PORT

# Try different protocol mimicry
masque-test.exe -noize -noize-mimic dns -endpoint IP:PORT

# Increase fragmentation
masque-test.exe -noize -noize-fragment 64 -endpoint IP:PORT
```

## Security Considerations

1. **Not Encryption**: Noize provides obfuscation, not additional encryption. QUIC already provides encryption.

2. **Traffic Analysis**: Heavy obfuscation makes traffic analysis harder but not impossible with advanced techniques.

3. **Active Probing**: GFW may actively probe servers. Use in combination with proper server configuration.

4. **Fingerprinting**: Custom patterns may create unique fingerprints. Rotate configurations periodically.

## Contributing

To add new obfuscation techniques:

1. Edit `masque/noize/noize.go`
2. Add new configuration options to `NoizeConfig`
3. Implement obfuscation logic in `ObfuscateWrite()`
4. Create preset in `masque/noize/conn.go`
5. Add CLI flags in `cmd/masque-test/main.go`

## Credits

Based on the AtomicNoize protocol originally developed for WireGuard obfuscation. Adapted and enhanced for QUIC/MASQUE with additional GFW bypass techniques.

## License

Same as parent project (vwarp).
