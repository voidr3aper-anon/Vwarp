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
vwarp --masque --noize-preset light -e 162.159.198.1:443

# Using configuration file (recommended)
vwarp --config my-config.json --masque
```

📖 **New to vwarp?** See the [Configuration Guide](docs/CONFIG_FORGE.md) for complete setup instructions.

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

- [Download the latest version from the releases page](https://github.com/voidr3aper-anon/Vwarp/releases)
- Basic understanding of VPN and proxy configurations

### Command Line Usage

```bash
# See all available options
vwarp -h

# Basic usage patterns
vwarp --masque --noize-preset <preset>    # MASQUE with obfuscation
vwarp --config <file> --masque            # Config file approach
vwarp --gool --key <key>                  # Warp-in-Warp mode
```

For complete CLI reference and configuration options, see the [Configuration Guide](docs/CONFIG_FORGE.md).

### Usage Examples

For comprehensive usage examples and configuration scenarios, see:
- **[Configuration Guide](docs/CONFIG_FORGE.md)** - Complete setup guide with examples
- **[SOCKS5 Proxy Guide](docs/SOCKS_PROXY_GUIDE.md)** - Double-VPN proxy chaining
- **[Production Deployment](docs/PRODUCTION_DEPLOYMENT.md)** - Enterprise setup and monitoring

### Psiphon Integration

vwarp supports Psiphon for additional censorship circumvention. Use `--cfon --country <CODE>` where CODE is a two-letter country code (US, CA, DE, etc.).

For complete country code list, see the [Configuration Guide](docs/CONFIG_FORGE.md).
![0](https://raw.githubusercontent.com/Ptechgithub/configs/main/media/line.gif)
### Termux

```
bash <(curl -fsSL https://raw.githubusercontent.com/voidr3aper-anon/Vwarp/master/termux.sh)
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
- **[Configuration Guide & Examples](docs/CONFIG_FORGE.md)** - Complete configuration reference with ready-to-use examples
- **[Sample Configuration Files](docs/examples/)** - JSON config templates
- **[Production Deployment](docs/PRODUCTION_DEPLOYMENT.md)** - Enterprise deployment, monitoring & scaling

### 🔗 Integration Guides  
- **[Complete Obfuscation Guide](docs/VWARP_OBFUSCATION_GUIDE.md)** - Advanced censorship bypass techniques
- **[SOCKS5 Proxy Chaining](docs/SOCKS_PROXY_GUIDE.md)** - Double-VPN and proxy routing



## 🛠️ Configuration

vwarp supports both CLI flags and configuration files. For production use, configuration files are recommended.

**Quick Setup:**
```bash
# Copy example config and customize
cp docs/examples/sample-working.json my-config.json
vwarp --config my-config.json --masque
```

**Complete configuration reference:** [Configuration Guide](docs/CONFIG_FORGE.md)

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
