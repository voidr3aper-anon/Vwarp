# vwarp

vwarp is an open-source implementation of Cloudflare's Warp, enhanced with Psiphon integration for circumventing censorship. This project aims to provide a robust and cross-platform VPN solution that can use psiphon on top of warp and warp-in-warp for changing the user virtual nat location.
<div align="center">

<img src="https://github.com/voidr3aper-anon/Vwarp/blob/master/logo/logo.png" width="350" alt="Vwarp Logo" />


**Maintainer**: [voidreaper](https://github.com/voidr3aper-anon)

**Check out the telegram channel**: 📱 [@VoidVerge](https://t.me/VoidVerge)

</div>
## 🚀 Quick Start

```bash
# Basic WARP connection
vwarp --bind 127.0.0.1:8086

# MASQUE mode with obfuscation
vwarp --masque --noize-preset moderate

# WireGuard with AtomicNoize obfuscation
vwarp --noize-preset heavy

# Warp-in-Warp (location changing)
vwarp --gool --key your-warp-license-key

# Using unified configuration file (recommended)
vwarp --config config/examples/complete-config.json --masque

# Through SOCKS5 proxy (double-VPN)
vwarp --proxy socks5://127.0.0.1:1080 --masque --noize-preset moderate
```

📖 **Need help?** Check out the [Configuration Guide](config/examples/README.md) and [Complete Obfuscation Guide](docs/VWARP_OBFUSCATION_GUIDE.md)

## Features

- **Warp Integration**: Leverages Cloudflare's Warp to provide a fast and secure VPN service.
- **MASQUE Tunneling**: Connect to Warp via MASQUE proxy protocol for enhanced censorship resistance.
- **MASQUE Noize Obfuscation**: Advanced QUIC packet obfuscation system to bypass Deep Packet Inspection (DPI).
- **AtomicNoize Protocol**: WireGuard obfuscation protocol for enhanced privacy and censorship resistance.
- **Unified Configuration**: Single configuration file format for all obfuscation methods.
- **Psiphon Chaining**: Integrates with Psiphon for censorship circumvention, allowing seamless access to the internet in restrictive environments.
- **Warp in Warp Chaining**: Chaining two instances of warp together to bypass location restrictions.
- **SOCKS5 Proxy Chaining**: Route WireGuard traffic through SOCKS5 proxies for double-VPN setups.
- **SOCKS5 Proxy Server**: Includes a SOCKS5 proxy server for secure and private browsing.

## Getting Started

### Prerequisites

- [Download the latest version from the releases page](https://github.com/bepass-org/vwarp/releases)
- Basic understanding of VPN and proxy configurations

### Usage

```
COMMAND
  vwarp

SUBCOMMANDS
  version   displays version

FLAGS
  -v, --verbose               enable verbose logging
  -4, --ipv4                  only use IPv4 for random warp/MASQUE endpoint
  -6                          only use IPv6 for random warp endpoint
  -b, --bind STRING           socks bind address (default: 127.0.0.1:8086)
  -e, --endpoint STRING       warp endpoint
  -k, --key STRING            warp key
      --dns STRING            DNS address (default: 1.1.1.1)
      --gool                  enable gool mode (warp in warp)
      --masque                enable MASQUE mode (connect to warp via MASQUE proxy)
      --masque-preferred      prefer MASQUE over WireGuard (with automatic fallback)
      --noize-preset STRING   noize preset: light, moderate, heavy (applies to active protocol)
      --noize-export STRING   export preset to JSON file (e.g., --noize-export moderate:config.json)
      --cfon                  enable psiphon mode (must provide country as well)
      --country STRING        psiphon country code (default: AT)
      --scan                  enable warp scanning
      --rtt DURATION           (default: 1s)
      --cache-dir STRING
      --fwmark UINT32          (default: 0)
      --reserved STRING
      --wgconf STRING
      --test-url STRING        (default: http://connectivity.cloudflareclient.com/cdn-cgi/trace)
  -c, --config STRING
      --proxy STRING          SOCKS5 proxy address to route WireGuard traffic through (e.g., socks5://127.0.0.1:1080)
```

### Basic Examples

#### Standard WARP Connection
```bash
vwarp --bind 127.0.0.1:8086
```

#### MASQUE Mode with Noize Obfuscation
```bash
# Light obfuscation (recommended for most users)
vwarp --masque --noize-preset light

# Heavy obfuscation for strict censorship
vwarp --masque --noize-preset heavy

# Using unified configuration file
vwarp --config config/examples/complete-config.json --masque
```

#### WireGuard with AtomicNoize Obfuscation
```bash
# Default WireGuard with moderate obfuscation
vwarp --noize-preset moderate

# Heavy obfuscation for censored networks
vwarp --noize-preset heavy --bind 127.0.0.1:8086
```

#### Through SOCKS5 Proxy (Double VPN)
```bash
# First, start your SOCKS5 proxy (e.g., SSH tunnel, VPN, etc.)
# Then route WARP through it:
vwarp --proxy socks5://127.0.0.1:1080 --bind 127.0.0.1:8086
```

#### With Psiphon for Censorship Circumvention
```bash
vwarp --cfon --country US --bind 127.0.0.1:8086
```

#### Warp-in-Warp (Change Location)
```bash
vwarp --gool --bind 127.0.0.1:8086
```

#### Maximum Privacy Setup
```bash
# Using CLI flags
vwarp \
  --proxy socks5://127.0.0.1:1080 \
  --masque \
  --noize-preset heavy \
  --verbose

# Using configuration file (recommended)
vwarp --config my-stealth-config.json --proxy socks5://127.0.0.1:1080
```

#### Scan for Best Endpoint
```bash
vwarp --scan --rtt 800ms
```

For more detailed examples and configurations, see:
- [Configuration Guide](config/examples/README.md) - Complete setup guide
- [SOCKS5 Proxy Guide](docs/SOCKS_PROXY_GUIDE.md) - Double-VPN setups
- [Obfuscation Guide](docs/VWARP_OBFUSCATION_GUIDE.md) - Advanced censorship bypass

### Country Codes for Psiphon

- Austria (AT)
- Australia (AU)
- Belgium (BE)
- Bulgaria (BG)
- Canada (CA)
- Switzerland (CH)
- Czech Republic (CZ)
- Germany (DE)
- Denmark (DK)
- Estonia (EE)
- Spain (ES)
- Finland (FI)
- France (FR)
- United Kingdom (GB)
- Croatia (HR)
- Hungary (HU)
- Ireland (IE)
- India (IN)
- Italy (IT)
- Japan (JP)
- Latvia (LV)
- Netherlands (NL)
- Norway (NO)
- Poland (PL)
- Portugal (PT)
- Romania (RO)
- Serbia (RS)
- Sweden (SE)
- Singapore (SG)
- Slovakia (SK)
- United States (US)
![0](https://raw.githubusercontent.com/Ptechgithub/configs/main/media/line.gif)
### Termux

```
bash <(curl -fsSL https://raw.githubusercontent.com/bepass-org/vwarp/master/termux.sh)
```
![1](https://github.com/Ptechgithub/configs/blob/main/media/18.jpg?raw=true)

- اگه حس کردی کانکت نمیشه یا خطا میده دستور `rm -rf .cache/vwarp` رو بزن و مجدد warp رو وارد کن.
- بعد از نصب برای اجرای مجدد فقط کافیه که `warp` یا `usef` یا `./warp` یا `vwarp`را وارد کنید. همش یکیه هیچ فرقی ندارد.
- اگر با 1 نصب نشد و خطا گرفتید ابتدا یک بار 3 را بزنید تا `Uninstall` شود سپس عدد 2 رو انتخاب کنید یعنی Arm.
- برای نمایش راهنما ` warp -h` را وارد کنید. 
- ای پی و پورت `127.0.0.1:8086`پروتکل socks
- در روش تبدیل اکانت  warp به warp plus (گزینه 6) مقدار ID را وارد میکنید. پس از اجرای warp دو اکانت برای شما ساخته شده که پس از انتخاب گزینه 6 خودش مقدار ID هر دو اکانت را پیدا میکند و شما باید هر بار یکی را انتخاب کنید و یا میتوانید با انتخاب manual مقدار ID دیگری را وارد کنید (مثلا برای خود برنامه ی 1.1.1.1 یا جای دیگر) با این کار هر 20 ثانیه 1 GB به اکانت شما اضافه میشود. و اکانت شما از حالت رایگان به پلاس تبدیل میشود. 
- برای تغییر  لوکیشن با استفاده از سایفون از طریق منو یا به صورت دستی (برای مثال به USA  از دستور  زیر استفاده کنید) 
- `warp --cfon --country US`
- برای اسکن ای پی سالم وارپ از دستور `warp --scan` استفاده کنید. 
- برای ترکیب (chain) دو کانفیگ برای تغییر لوکیشن از دستور `warp --gool` استفاده کنید. 

## 📚 Documentation

### 📦 Configuration & Setup
- **[Unified Configuration Guide](config/examples/README.md)** - Complete configuration reference with all options
- **[Sample Configurations](config/examples/)** - Production-ready config examples  
- **[Configuration Examples](docs/examples/README.md)** - Obfuscation configurations for different scenarios
- **[Production Deployment](docs/PRODUCTION_DEPLOYMENT.md)** - Enterprise deployment, monitoring & scaling

### 🔗 Integration Guides  
- **[Complete Obfuscation Guide](docs/VWARP_OBFUSCATION_GUIDE.md)** - Advanced censorship bypass techniques
- **[SOCKS5 Proxy Chaining](docs/SOCKS_PROXY_GUIDE.md)** - Double-VPN and proxy routing

### 🚀 Quick Examples

**Lightweight Setup (Fast)**
```bash
vwarp --masque --noize-preset light
```

**Balanced Setup (Recommended)**  
```json
// my-config.json
{
  "bind": "127.0.0.1:8086",
  "endpoint": "162.159.192.1:2408", 
  "masque": {
    "enabled": true,
    "config": {
      "Jc": 15,
      "MimicProtocol": "https",
      "fragment_initial": true
    }
  }
}
```
```bash
vwarp --config my-config.json
```

**Maximum Stealth (Heavy Obfuscation)**
```bash
vwarp --config config/examples/complete-config.json --proxy socks5://127.0.0.1:1080
```

## 🛠️ Configuration Examples

### Basic Configuration File
```json
{
  "version": "1.0",
  "bind": "127.0.0.1:8086",
  "endpoint": "162.159.192.1:2408",
  "key": "your-warp-license-key-here",
  "dns": "1.1.1.1",
  "masque": {
    "enabled": true,
    "config": {
      "Jc": 15,
      "MimicProtocol": "https",
      "fragment_initial": true,
      "RandomPadding": true
    }
  }
}
```

### Usage with Config File
```bash
# Create config file
cp config/examples/complete-config.json my-production.json

# Edit your settings
nano my-production.json

# Run with MASQUE mode
vwarp --config my-production.json --masque

# Run with WireGuard mode (default)
vwarp --config my-production.json

# Run with Warp-in-Warp mode
vwarp --config my-production.json --gool
```

### Key Configuration Fields

| Field | Description | Example |
|-------|-------------|----------|
| `bind` | SOCKS5 proxy listen address | `"127.0.0.1:8086"` |
| `endpoint` | Cloudflare WARP endpoint | `"162.159.192.1:2408"` |
| `key` | WARP+ license key (optional) | `"your-key-here"` |
| `proxy` | Upstream SOCKS5 proxy | `"socks5://127.0.0.1:1080"` |
| `masque.enabled` | Enable MASQUE mode | `true` |
| `wireguard.reserved` | Reserved bytes (decimal) | `"1,2,3"` |

⚠️ **Important**: Reserved bytes must be in decimal format (`"1,2,3"`) not hex (`"0x01,0x02,0x03"`)

## Acknowledgements

- **Maintainer**: [voidreaper](https://github.com/voidr3aper-anon)
- Cloudflare Warp
- Psiphon
- WireGuard Protocol
- Original Bepass-org team
- All contributors and supporters of this project

## License

This repository is a fork of [vwarp] (MIT licensed).
Original files are © their respective authors and remain under the MIT License.
All additional changes and new files in this fork are © voidreaper and licensed under [LICENSE-GPL-3.0], see LICENSE-GPL-3.0. all new feature tricks and ideas are not allowed to copy or pull from this  repo to the main repo or other similar project unless the maintainers have granted permission.


## Moto 
 Beside Licensing , we honor the main developer of the code yousef Ghobadi ,and We coutinue the way of actively help the people access internet of freedom. We are legion. 
