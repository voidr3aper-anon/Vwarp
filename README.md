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

- [Download the latest version from the releases page](https://github.com/voidr3aper-anon/vwarp/releases)
- Basic understanding of VPN and proxy configurations

### Command Line Usage

```bash
# See all available options
vwarp -h

# Basic usage patterns
vwarp --config my-config.json             # Give a Config File 
vwarp --masque --noize-preset <preset>    # MASQUE with obfuscation
vwarp --gool 
vwarp --config <file> --masque            # Config file approach with proto  prefer(can be determind in the config file)
vwarp --config <file> --gool              # Warp-in-Warp mode with config 
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

## 📚 Documentation

### 📦 Configuration & Setup
- **[Configuration Guide & Examples](docs/CONFIG_FORGE.md)** - Complete configuration reference with ready-to-use examples
- **[Sample Configuration Files](docs/examples/)** - JSON config templates
- **[Production Deployment](docs/PRODUCTION_DEPLOYMENT.md)** - Enterprise deployment, monitoring & scaling

### 🔗 Integration Guides  
- **[Complete Obfuscation Guide](docs/VWARP_OBFUSCATION_GUIDE.md)** - Advanced censorship bypass techniques
- **[SOCKS5 Proxy Chaining](docs/SOCKS_PROXY_GUIDE.md)** - Double-VPN and proxy routing



##  Configuration

vwarp supports both CLI flags and configuration files. For production use, configuration files are recommended.

**Quick Setup:**
```bash
# Copy example config and customize
cp docs/examples/sample-working.json my-config.json
vwarp --config my-config.json --masque
```

**Complete configuration reference:** [Configuration Guide](docs/CONFIG_FORGE.md)

## License

This repository is a fork of [vwarp] (MIT licensed).
Original files are © their respective authors and remain under the MIT License.
All additional changes and new files in this fork are © voidreaper and licensed under [LICENSE-GPL-3.0], see LICENSE-GPL-3.0. all new feature tricks and ideas are not allowed to copy or pull from this  repo to the main repo or other similar project unless the maintainers have granted permission.


## Acknowledgements

- **Maintainer**: [voidreaper](https://github.com/voidr3aper-anon)
- Cloudflare Warp
- Psiphon
- WireGuard Protocol
- Original Bepass-org team
- All contributors and supporters of this project
- 
## Moto 
 Beside Licensing , we honor the main developer of the code yousef Ghobadi ,and We coutinue the way of actively help the people access internet of freedom. We are legion. 
