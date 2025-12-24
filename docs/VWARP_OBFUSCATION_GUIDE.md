# vwarp Complete Obfuscation Guide

This comprehensive guide covers all obfuscation technologies available in vwarp for bypassing censorship and Deep Packet Inspection (DPI). 

**🎯 Unified Configuration**: vwarp now uses a single, unified configuration file format that combines all settings (connection, obfuscation, proxy, etc.) in one place. No more scattered command-line flags!
## Table of Contents

1. [Overview](#overview)
2. [MASQUE Noize Obfuscation](#masque-noize-obfuscation)
3. [AtomicNoize Protocol](#atomicnoize-protocol)  
4. [Configuration Reference](#configuration-reference)
5. [Usage Examples](#usage-examples)
6. [Troubleshooting](#troubleshooting)

## Overview

vwarp provides two main obfuscation technologies:

- **MASQUE Noize**: Obfuscates QUIC traffic at the MASQUE tunnel level
- **AtomicNoize**: Obfuscates WireGuard traffic directly

Both can be used together or separately depending on your censorship circumvention needs.

## MASQUE Noize Obfuscation

### What is MASQUE Noize?

MASQUE Noize is a sophisticated packet obfuscation system that disguises QUIC traffic patterns to bypass DPI systems. It operates at the UDP packet level, transforming QUIC handshake patterns through multiple techniques.

### How It Works

**Original QUIC Flow:**
```
Client ──[Initial]──> Server
Client <──[Response]── Server  
Client ──[1-RTT]────> Server
```

**Noize-Obfuscated Flow:**
```
Client ──[I1 Sig]───> Server (signature packet)
Client ──[I2 Sig]───> Server (signature packet) 
Client ──[Junk1]────> Server (decoy traffic)
Client ──[Initial*]──> Server (real QUIC, obfuscated)
Client <──[Response]── Server
Client ──[Junk2]────> Server (post-handshake noise)
Client ──[1-RTT]────> Server
```

### Core Techniques

1. **Signature Packet Injection (I1-I5)**: Sends predefined signature packets that mimic legitimate protocols
2. **Junk Packet Generation**: Creates decoy UDP packets with configurable timing and sizes
3. **Protocol Mimicry**: Makes traffic appear as HTTP/HTTPS, DNS, or STUN protocols
4. **Timing Obfuscation**: Introduces controlled delays to break fingerprinting patterns
5. **Packet Fragmentation**: Splits initial packets to avoid signature detection
6. **Dynamic Padding**: Adds random data to alter packet size patterns

### MASQUE Noize Configuration

#### Using Presets (Recommended)

```bash
# Light obfuscation - minimal overhead, basic DPI evasion
vwarp --masque --masque-noize --masque-noize-preset light

# Heavy obfuscation - maximum protection for strict censorship
vwarp --masque --masque-noize --masque-noize-preset heavy

# Custom configuration file
vwarp --masque --masque-noize --masque-noize-config custom.json
```

#### Configuration File Format

```json
{
  "masque": {
    "enabled": true,
    "config": {
      "i1": "<b 0d0a0d0a>",
      "i2": "<b 0xc70000...>", 
      "i3": "",
      "i4": "",
      "i5": "",
      "Jc": 10,
      "Jmin": 40,
      "Jmax": 90,
      "JcBeforeHS": 2,
      "JcAfterI1": 1, 
      "JcDuringHS": 3,
      "JcAfterHS": 2,
      "JunkInterval": 15000000,
      "HandshakeDelay": 10000000,
      "MimicProtocol": "quic",
      "FragmentInitial": false,
      "FragmentSize": 0,
      "PaddingMin": 0,
      "PaddingMax": 0,
      "RandomPadding": false,
      "AllowZeroSize": true
    }
  }
}
```

#### Parameter Reference

| Parameter | Type | Description | Default | Range |
|-----------|------|-------------|---------|-------|
| `i1` to `i5` | string | Signature packets in CPS format | "" | CPS format |
| `Jc` | integer | Total junk packets to send | 10 | 0-100 |
| `Jmin`/`Jmax` | integer | Junk packet size range (bytes) | 40/90 | 1-1400 |
| `JcBeforeHS` | integer | Junk packets before handshake | 2 | 0-Jc |
| `JcAfterI1` | integer | Junk packets after I1 signature | 1 | 0-Jc |
| `JcDuringHS` | integer | Junk packets during handshake | 3 | 0-Jc |
| `JcAfterHS` | integer | Junk packets after handshake | 2 | 0-Jc |
| `JunkInterval` | integer | Delay between junk packets (nanoseconds) | 15000000 | 1000000-1000000000 |
| `HandshakeDelay` | integer | Delay before handshake (nanoseconds) | 10000000 | 0-1000000000 |
| `MimicProtocol` | string | Protocol to imitate | "quic" | quic, https, dns, stun |
| `FragmentInitial` | boolean | Fragment initial QUIC packets | false | true/false |
| `FragmentSize` | integer | Fragment size for initial packets | 0 | 0-1400 |
| `PaddingMin`/`PaddingMax` | integer | Padding size range (bytes) | 0/0 | 0-1400 |
| `RandomPadding` | boolean | Use random padding | false | true/false |
| `AllowZeroSize` | boolean | Allow zero-size junk packets | true | true/false |

## AtomicNoize Protocol  

### What is AtomicNoize?

AtomicNoize is a WireGuard obfuscation protocol that makes VPN traffic appear as legitimate IPsec/IKEv2 traffic. It works by wrapping WireGuard packets with special headers and injecting decoy traffic.

### How It Works

**Original WireGuard Flow:**
```
Client ──[Handshake Init]──> Server
Client <──[Handshake Response]── Server
Client ──[Data Packets]────> Server
```

**AtomicNoize-Obfuscated Flow:**
```
Client ──[I1 Signature]────> Server (IKE-like packet)
Client ──[Junk Packets]────> Server (decoy IPsec traffic)
Client ──[Obfuscated Init]──> Server (wrapped WireGuard)
Client <──[Obfuscated Resp]── Server
Client ──[Obfuscated Data]──> Server
```

### Core Features

1. **IKEv2/IPsec Mimicry**: Wraps packets to look like legitimate VPN protocols
2. **Signature Packets**: Configurable I1-I5 packets that establish protocol context
3. **Junk Traffic Generation**: Creates realistic IPsec-like noise traffic
4. **Same-Port Architecture**: Maintains NAT/firewall compatibility
5. **Flexible Timing Control**: Precise control over when obfuscation occurs

### AtomicNoize Configuration

#### Configuration File Format

```json
{
  "wireguard": {
    "enabled": true,
    "atomicnoize": {
      "I1": "<b 0c0d0e0f>",
      "I2": "<b 0xc70000...>",
      "I3": "",
      "I4": "",  
      "I5": "",
      "S1": 1,
      "S2": 2,
      "Jc": 85,
      "Jmin": 40,
      "Jmax": 90,
      "JcAfterI1": 2,
      "JcBeforeHS": 2,
      "JcAfterHS": 2,
      "JunkInterval": 150000000,
      "AllowZeroSize": true,
      "HandshakeDelay": 15000000
    }
  }
}
```

#### Parameter Reference

| Parameter | Type | Description | Default | Range |
|-----------|------|-------------|---------|-------|
| `I1` to `I5` | string | Signature packets in CPS format | "" | CPS format |
| `S1`/`S2` | integer | Packet prefixes (use with caution) | 0 | 0-255 |
| `Jc` | integer | Total junk packets | 85 | 0-200 |
| `Jmin`/`Jmax` | integer | Junk packet size range (bytes) | 40/90 | 1-1400 |
| `JcAfterI1` | integer | Junk packets after I1 signature | 2 | 0-Jc |
| `JcBeforeHS` | integer | Junk packets before WireGuard handshake | 2 | 0-Jc |
| `JcAfterHS` | integer | Junk packets after handshake | 2 | 0-Jc |
| `JunkInterval` | integer | Delay between junk packets (nanoseconds) | 150000000 | 1000000-1000000000 |
| `HandshakeDelay` | integer | Delay before WireGuard handshake (nanoseconds) | 15000000 | 0-1000000000 |
| `AllowZeroSize` | boolean | Allow zero-size junk packets | true | true/false |

## Configuration Reference

### CPS (Custom Packet Specification) Format

Both MASQUE Noize and AtomicNoize use CPS format for signature packets:

- `<b XX>` - Single byte in hex (e.g., `<b 0d>`)
- `<b XXXX>` - Multiple bytes in hex (e.g., `<b 0d0a0d0a>`)  
- `<b 0xXXXX...>` - Long hex string (e.g., `<b 0xc70000000108ce1b...>`)
- `<r N>` - N random bytes (e.g., `<r 4>`)

### Time Formats

All timing parameters use nanoseconds:
- `10000000` = 10 milliseconds
- `150000000` = 150 milliseconds  
- `1000000000` = 1 second

## Usage Examples

### Example 1: Light MASQUE Obfuscation

```bash
vwarp --masque --masque-noize --masque-noize-config light-config.json
```

**light-config.json:**
```json
{
  "masque": {
    "enabled": true,
    "config": {
      "i1": "<b 0d0a0d0a>",
      "Jc": 5,
      "Jmin": 20,
      "Jmax": 50,
      "JcBeforeHS": 1,
      "JcDuringHS": 2,
      "JcAfterHS": 1,
      "JunkInterval": 10000000,
      "HandshakeDelay": 5000000,
      "MimicProtocol": "https",
      "AllowZeroSize": false
    }
  }
}
```

### Example 2: Heavy AtomicNoize Obfuscation

```bash
vwarp --config heavy-atomic-config.json
```

**heavy-atomic-config.json:**
```json
{
  "wireguard": {
    "enabled": true,
    "atomicnoize": {
      "I1": "<b 0c0d0e0f>",
      "I2": "<b 0xc70000000108ce1b...>",
      "Jc": 150,
      "Jmin": 50,
      "Jmax": 200,
      "JcAfterI1": 5,
      "JcBeforeHS": 10,
      "JcAfterHS": 5,
      "JunkInterval": 200000000,
      "HandshakeDelay": 50000000,
      "AllowZeroSize": true
    }
  }
}
```

### Example 3: Combined MASQUE + AtomicNoize

```bash
vwarp --config ultimate-config.json
```

**ultimate-config.json:**
```json
{
  "wireguard": {
    "enabled": true,
    "atomicnoize": {
      "I1": "<b 0c0d0e0f>",
      "Jc": 50,
      "JcBeforeHS": 3,
      "JunkInterval": 100000000
    }
  },
  "masque": {
    "enabled": true,
    "config": {
      "i1": "<b 0d0a0d0a>",
      "Jc": 20,
      "JcDuringHS": 5,
      "MimicProtocol": "https"
    }
  }
}
```

## Troubleshooting

### Common Issues

**Connection Fails with Obfuscation Enabled:**
- Try reducing junk packet count (`Jc`)
- Increase timing intervals (`JunkInterval`, `HandshakeDelay`)
- Disable zero-size packets (`AllowZeroSize: false`)

**Performance Issues:**
- Reduce junk packet sizes (`Jmin`, `Jmax`)
- Decrease junk packet count (`Jc`)
- Increase timing intervals to reduce packet rate

**Still Being Blocked:**
- Try different `MimicProtocol` values (https, dns, stun)
- Use longer, more complex signature packets (I1-I5)
- Enable packet fragmentation (`FragmentInitial: true`)

### Debug Options

Enable debug logging with environment variable:
```bash
export VWARP_NOIZE_DEBUG=1
vwarp --masque --masque-noize --masque-noize-config config.json
```

### Preset Configurations

vwarp includes several built-in presets:

- **light**: Minimal obfuscation, best performance
- **medium**: Balanced obfuscation and performance  
- **heavy**: Maximum obfuscation, may impact speed
- **stealth**: Advanced protocol mimicry
- **gfw**: Optimized for China's Great Firewall

Use presets with:
```bash
vwarp --masque --masque-noize --masque-noize-preset heavy
```

## Security Considerations

1. **Signature Packets**: Use unique I1-I5 signatures to avoid detection patterns
2. **Timing Randomization**: Vary timing parameters to prevent fingerprinting
3. **Protocol Selection**: Choose `MimicProtocol` based on your network environment
4. **Packet Sizes**: Use realistic size ranges for your chosen protocol mimicry

## Performance Tuning

1. **Start Light**: Begin with light obfuscation and increase as needed
2. **Monitor Bandwidth**: Junk packets consume additional bandwidth
3. **Adjust Timing**: Balance obfuscation effectiveness with connection latency
4. **Test Incrementally**: Change one parameter at a time to identify optimal settings

For additional help, check the [vwarp GitHub repository](https://github.com/voidr3aper-anon/Vwarp) or join our [Telegram channel](https://t.me/VoidVerge).