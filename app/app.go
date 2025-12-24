package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path"
	"sync"
	"time"

	"github.com/voidr3aper-anon/Vwarp/config/noize"
	"github.com/voidr3aper-anon/Vwarp/iputils"
	"github.com/voidr3aper-anon/Vwarp/masque"
	masquenoize "github.com/voidr3aper-anon/Vwarp/masque/noize"
	"github.com/voidr3aper-anon/Vwarp/psiphon"
	"github.com/voidr3aper-anon/Vwarp/warp"
	"github.com/voidr3aper-anon/Vwarp/wireguard/preflightbind"
	"github.com/voidr3aper-anon/Vwarp/wireguard/tun"
	"github.com/voidr3aper-anon/Vwarp/wireguard/tun/netstack"
	"github.com/voidr3aper-anon/Vwarp/wiresocks"
)

const singleMTU = 1280 // MASQUE/QUIC tunnel MTU (standard MTU matching usque)
const doubleMTU = 1280 // minimum mtu for IPv6, may cause frag reassembly somewhere

type WarpOptions struct {
	Bind               netip.AddrPort
	Endpoint           string
	License            string
	DnsAddr            netip.Addr
	Psiphon            *PsiphonOptions
	Gool               bool
	Masque             bool
	MasquePreferred    bool   // Prefer MASQUE over WireGuard with automatic fallback
	MasqueNoize        bool   // Enable MASQUE noize obfuscation
	MasqueNoizePreset  string // Noize preset: light, medium, heavy, stealth, gfw
	MasqueNoizeConfig  string // Path to custom noize configuration JSON file
	Scan               *wiresocks.ScanOptions
	CacheDir           string
	FwMark             uint32
	WireguardConfig    string
	Reserved           string
	TestURL            string
	AtomicNoizeConfig  *preflightbind.AtomicNoizeConfig
	UnifiedNoizeConfig *noize.UnifiedNoizeConfig // Unified configuration for both WireGuard and MASQUE obfuscation
	ProxyAddress       string
}

type PsiphonOptions struct {
	Country string
}

func RunWarp(ctx context.Context, l *slog.Logger, opts WarpOptions) error {
	if opts.WireguardConfig != "" {
		if err := runWireguard(ctx, l, opts); err != nil {
			return err
		}

		return nil
	}

	if opts.Psiphon != nil && opts.Gool {
		return errors.New("can't use psiphon and gool at the same time")
	}

	if opts.Masque && opts.Gool {
		return errors.New("can't use masque and gool at the same time")
	}

	if opts.Masque && opts.Psiphon != nil {
		return errors.New("can't use masque and psiphon at the same time")
	}

	if opts.Psiphon != nil && opts.Psiphon.Country == "" {
		return errors.New("must provide country for psiphon")
	}

	// Decide Working Scenario
	endpoints := []string{opts.Endpoint, opts.Endpoint}

	if opts.Scan != nil {
		// make primary identity
		ident, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "primary"), opts.License)
		if err != nil {
			l.Error("couldn't load primary warp identity")
			return err
		}

		// Reading the private key from the 'Interface' section
		opts.Scan.PrivateKey = ident.PrivateKey

		// Reading the public key from the 'Peer' section
		opts.Scan.PublicKey = ident.Config.Peers[0].PublicKey

		res, err := wiresocks.RunScan(ctx, l, *opts.Scan)
		if err != nil {
			return err
		}

		l.Debug("scan results", "endpoints", res)

		endpoints = make([]string, len(res))
		for i := 0; i < len(res); i++ {
			endpoints[i] = res[i].AddrPort.String()
		}
	}
	l.Info("using warp endpoints", "endpoints", endpoints)

	var warpErr error
	switch {
	case opts.Masque:
		l.Info("running in MASQUE mode")
		// run warp through MASQUE proxy
		warpErr = runWarpWithMasque(ctx, l, opts, endpoints[0])
	case opts.MasquePreferred:
		// Try MASQUE first, fallback to WireGuard automatically
		l.Info("running in MASQUE-preferred mode")
		warpErr = runWarpWithMasque(ctx, l, opts, endpoints[0])

		if warpErr != nil {
			l.Warn("MASQUE preferred but failed, falling back to WireGuard", "error", warpErr)
			warpErr = runWarp(ctx, l, opts, endpoints[0])
			if warpErr == nil {
				l.Info("WireGuard fallback successful")
			}
		} else {
			l.Info("MASQUE preferred mode successful")
		}
	case opts.Psiphon != nil:
		l.Info("running in Psiphon (cfon) mode")
		// run primary warp on a random tcp port and run psiphon on bind address
		warpErr = runWarpWithPsiphon(ctx, l, opts, endpoints[0])
	case opts.Gool:
		l.Info("running in warp-in-warp (gool) mode")
		// run warp in warp
		warpErr = runWarpInWarp(ctx, l, opts, endpoints)
	default:
		l.Info("running in normal warp mode")
		// just run primary warp on bindAddress
		warpErr = runWarp(ctx, l, opts, endpoints[0])
	}

	return warpErr
}

func runWireguard(ctx context.Context, l *slog.Logger, opts WarpOptions) error {
	conf, err := wiresocks.ParseConfig(opts.WireguardConfig)
	if err != nil {
		return err
	}

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable trick and keepalive on all peers in config
	atomicNoizeConfig := getAtomicNoizeConfig(opts)
	for i, peer := range conf.Peers {
		// Only enable old trick functionality if AtomicNoize is not being used
		if atomicNoizeConfig == nil {
			peer.Trick = true
		}
		peer.KeepAlive = 5

		// Try resolving if the endpoint is a domain
		addr, err := iputils.ParseResolveAddressPort(peer.Endpoint, false, opts.DnsAddr.String())
		if err == nil {
			peer.Endpoint = addr.String()
		}

		conf.Peers[i] = peer
	}

	// Establish wireguard on userspace stack
	var werr error
	var tnet *netstack.Net
	var tunDev tun.Device
	for _, t := range []string{"t1", "t2"} {
		// Create userspace tun network stack
		tunDev, tnet, werr = netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
		if werr != nil {
			continue
		}

		werr = establishWireguard(ctx, l, conf, tunDev, opts.FwMark, t, atomicNoizeConfig, opts.ProxyAddress)
		if werr != nil {
			continue
		}

		// Test wireguard connectivity
		werr = usermodeTunTest(ctx, l, tnet, opts.TestURL)
		if werr != nil {
			continue
		}
		break
	}
	if werr != nil {
		return werr
	}

	// Run a proxy on the userspace stack
	actualBind, err := wiresocks.StartProxy(ctx, l, tnet, opts.Bind)
	if err != nil {
		return err
	}

	l.Info("serving proxy", "address", actualBind)

	return nil
}

func runWarp(ctx context.Context, l *slog.Logger, opts WarpOptions, endpoint string) error {
	// make primary identity
	ident, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "primary"), opts.License)
	if err != nil {
		l.Error("couldn't load primary warp identity")
		return err
	}

	conf := generateWireguardConfig(ident)
	atomicNoizeConfig := getAtomicNoizeConfig(opts)

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable trick and keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = endpoint
		// Only enable old trick functionality if AtomicNoize is not being used
		if opts.AtomicNoizeConfig == nil {
			peer.Trick = true
		}
		peer.KeepAlive = 5

		if opts.Reserved != "" {
			r, err := wiresocks.ParseReserved(opts.Reserved)
			if err != nil {
				return err
			}
			peer.Reserved = r
		}

		conf.Peers[i] = peer
	}

	// Establish wireguard on userspace stack
	var werr error
	var tnet *netstack.Net
	var tunDev tun.Device
	for _, t := range []string{"t1", "t2"} {
		tunDev, tnet, werr = netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
		if werr != nil {
			continue
		}

		werr = establishWireguard(ctx, l, &conf, tunDev, opts.FwMark, t, atomicNoizeConfig, opts.ProxyAddress)
		if werr != nil {
			continue
		}

		// Test wireguard connectivity
		werr = usermodeTunTest(ctx, l, tnet, opts.TestURL)
		if werr != nil {
			continue
		}
		break
	}
	if werr != nil {
		return werr
	}

	// Run a proxy on the userspace stack
	actualBind, err := wiresocks.StartProxy(ctx, l, tnet, opts.Bind)
	if err != nil {
		return err
	}

	l.Info("serving proxy", "address", actualBind)
	return nil
}

func runWarpInWarp(ctx context.Context, l *slog.Logger, opts WarpOptions, endpoints []string) error {
	atomicNoizeConfig := getAtomicNoizeConfig(opts)
	// make primary identity
	ident1, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "primary"), opts.License)
	if err != nil {
		l.Error("couldn't load primary warp identity")
		return err
	}

	conf := generateWireguardConfig(ident1)

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable trick and keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = endpoints[0]
		// Only enable old trick functionality if AtomicNoize is not being used
		if opts.AtomicNoizeConfig == nil {
			peer.Trick = true
		}
		peer.KeepAlive = 5

		if opts.Reserved != "" {
			r, err := wiresocks.ParseReserved(opts.Reserved)
			if err != nil {
				return err
			}
			peer.Reserved = r
		}

		conf.Peers[i] = peer
	}

	// Establish wireguard on userspace stack and bind the wireguard sockets to the default interface and apply
	var werr error
	var tnet1 *netstack.Net
	var tunDev tun.Device
	for _, t := range []string{"t1", "t2"} {
		// Create userspace tun network stack
		tunDev, tnet1, werr = netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
		if werr != nil {
			continue
		}

		werr = establishWireguard(ctx, l.With("gool", "outer"), &conf, tunDev, opts.FwMark, t, atomicNoizeConfig, opts.ProxyAddress)
		if werr != nil {
			continue
		}

		// Test wireguard connectivity
		werr = usermodeTunTest(ctx, l, tnet1, opts.TestURL)
		if werr != nil {
			continue
		}
		break
	}
	if werr != nil {
		return werr
	}

	// Create a UDP port forward between localhost and the remote endpoint
	addr, err := wiresocks.NewVtunUDPForwarder(ctx, netip.MustParseAddrPort("127.0.0.1:0"), endpoints[0], tnet1, singleMTU)
	if err != nil {
		return err
	}

	// make secondary
	ident2, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "secondary"), opts.License)
	if err != nil {
		l.Error("couldn't load secondary warp identity")
		return err
	}

	conf = generateWireguardConfig(ident2)

	// Set up MTU
	conf.Interface.MTU = doubleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = addr.String()
		peer.KeepAlive = 20

		if opts.Reserved != "" {
			r, err := wiresocks.ParseReserved(opts.Reserved)
			if err != nil {
				return err
			}
			peer.Reserved = r
		}

		conf.Peers[i] = peer
	}

	// Create userspace tun network stack
	tunDev, tnet2, err := netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
	if err != nil {
		return err
	}

	// Establish wireguard on userspace stack
	if err := establishWireguard(ctx, l.With("gool", "inner"), &conf, tunDev, opts.FwMark, "t0", nil, ""); err != nil {
		return err
	}

	// Test wireguard connectivity
	if err := usermodeTunTest(ctx, l, tnet2, opts.TestURL); err != nil {
		return err
	}

	actualBind, err := wiresocks.StartProxy(ctx, l, tnet2, opts.Bind)
	if err != nil {
		return err
	}

	l.Info("serving proxy", "address", actualBind)
	return nil
}

func runWarpWithPsiphon(ctx context.Context, l *slog.Logger, opts WarpOptions, endpoint string) error {
	// make primary identity
	ident, err := warp.LoadOrCreateIdentity(l, path.Join(opts.CacheDir, "primary"), opts.License)
	if err != nil {
		l.Error("couldn't load primary warp identity")
		return err
	}

	conf := generateWireguardConfig(ident)
	atomicNoizeConfig := getAtomicNoizeConfig(opts)

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{opts.DnsAddr}

	// Enable trick and keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = endpoint
		// Only enable old trick functionality if AtomicNoize is not being used
		if opts.AtomicNoizeConfig == nil {
			peer.Trick = true
		}
		peer.KeepAlive = 5

		if opts.Reserved != "" {
			r, err := wiresocks.ParseReserved(opts.Reserved)
			if err != nil {
				return err
			}
			peer.Reserved = r
		}

		conf.Peers[i] = peer
	}

	// Establish wireguard on userspace stack
	var werr error
	var tnet *netstack.Net
	var tunDev tun.Device
	for _, t := range []string{"t1", "t2"} {
		// Create userspace tun network stack
		tunDev, tnet, werr = netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
		if werr != nil {
			continue
		}

		werr = establishWireguard(ctx, l, &conf, tunDev, opts.FwMark, t, atomicNoizeConfig, opts.ProxyAddress)
		if werr != nil {
			continue
		}

		// Test wireguard connectivity
		werr = usermodeTunTest(ctx, l, tnet, opts.TestURL)
		if werr != nil {
			continue
		}
		break
	}
	if werr != nil {
		return werr
	}

	// Run a proxy on the userspace stack
	warpBind, err := wiresocks.StartProxy(ctx, l, tnet, netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		return err
	}

	// run psiphon
	err = psiphon.RunPsiphon(ctx, l.With("subsystem", "psiphon"), warpBind, opts.CacheDir, opts.Bind, opts.Psiphon.Country)
	if err != nil {
		return fmt.Errorf("unable to run psiphon %w", err)
	}

	l.Info("serving proxy", "address", opts.Bind)
	return nil
}

// getAtomicNoizeConfig extracts AtomicNoize configuration from options
func getAtomicNoizeConfig(opts WarpOptions) *preflightbind.AtomicNoizeConfig {
	// Check unified config first
	if opts.UnifiedNoizeConfig != nil && opts.UnifiedNoizeConfig.IsWireGuardEnabled() {
		return opts.UnifiedNoizeConfig.WireGuard.AtomicNoize
	}
	// Fallback to legacy config
	return opts.AtomicNoizeConfig
}

// getMASQUEPresetConfig returns the MASQUE noize configuration for a given preset
func getMASQUEPresetConfig(preset string, l *slog.Logger) *masquenoize.NoizeConfig {
	switch preset {
	case "minimal":
		return masquenoize.MinimalObfuscationConfig()
	case "light":
		return masquenoize.LightObfuscationConfig()
	case "medium":
		return masquenoize.MediumObfuscationConfig()
	case "heavy":
		return masquenoize.HeavyObfuscationConfig()
	case "stealth":
		return masquenoize.StealthObfuscationConfig()
	case "gfw":
		return masquenoize.GFWBypassConfig()
	case "firewall":
		return masquenoize.FirewallBypassConfig()
	case "none":
		return nil
	default:
		l.Warn("Unknown MASQUE noize preset, using medium", "preset", preset)
		return masquenoize.MediumObfuscationConfig()
	}
}

func runWarpWithMasque(ctx context.Context, l *slog.Logger, opts WarpOptions, endpoint string) error {
	l.Info("running in MASQUE mode")

	// Check network MTU compatibility for MASQUE
	iputils.DetectAndCheckMTUForMasque(l)

	// Convert endpoint to MASQUE endpoint (port 443)
	// The endpoint may be from scanner (port 2408) or user-provided (any port)
	var masqueEndpoint string
	l.Info("using endpoint as MASQUE server", "endpoint", endpoint)
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		// Successfully split, use the host with port 443
		masqueEndpoint = net.JoinHostPort(host, "443")
		l.Debug("Converted endpoint to MASQUE endpoint", "from", endpoint, "to", masqueEndpoint)
	} else {
		// No port specified, assume it's just a host, add port 443
		masqueEndpoint = net.JoinHostPort(endpoint, "443")
		l.Debug("Added MASQUE port to endpoint", "from", endpoint, "to", masqueEndpoint)
	}

	// Create MASQUE adapter using usque library
	masqueConfigPath := path.Join(opts.CacheDir, "masque_config.json")
	l.Debug("Creating MASQUE adapter", "masqueEndpoint", masqueEndpoint, "configPath", masqueConfigPath)

	// Configure noize obfuscation using unified configuration system
	var noizeConfig *masquenoize.NoizeConfig

	// Check for unified configuration first
	if opts.UnifiedNoizeConfig != nil && opts.UnifiedNoizeConfig.IsMASQUEEnabled() {
		l.Info("Using unified MASQUE noize configuration")
		masqueConfig := opts.UnifiedNoizeConfig.MASQUE

		if masqueConfig.Config != nil {
			// Use custom configuration
			noizeConfig = masqueConfig.Config
			l.Info("Using custom unified MASQUE noize configuration")
		} else if masqueConfig.Preset != "" {
			// Use preset from unified config
			l.Info("Using unified MASQUE noize preset", "preset", masqueConfig.Preset)
			noizeConfig = getMASQUEPresetConfig(masqueConfig.Preset, l)
		}
	} else if opts.MasqueNoize {
		// Fallback to legacy configuration for backward compatibility
		l.Info("Using legacy MASQUE noize configuration")

		// Check for custom config file first
		if opts.MasqueNoizeConfig != "" {
			l.Info("Loading custom MASQUE noize configuration", "configPath", opts.MasqueNoizeConfig)
			customConfig, err := masquenoize.LoadConfigFromFile(opts.MasqueNoizeConfig)
			if err != nil {
				l.Warn("Failed to load custom noize config, falling back to preset", "error", err, "preset", opts.MasqueNoizePreset)
			} else {
				noizeConfig = customConfig
				l.Info("Custom noize configuration loaded successfully")
			}
		}

		// Use preset if no custom config loaded
		if noizeConfig == nil {
			preset := opts.MasqueNoizePreset
			if preset == "" {
				preset = "medium"
			}
			l.Info("Using legacy MASQUE noize preset", "preset", preset)
			noizeConfig = getMASQUEPresetConfig(preset, l)
		}
	}

	// Create MASQUE adapter with retry for Android connectivity issues
	var adapter *masque.MasqueAdapter
	var err error

	// Try creating adapter with retries for Android initialization issues
	for attempt := 1; attempt <= 3; attempt++ {
		l.Debug("Creating MASQUE adapter", "attempt", attempt)

		adapter, err = masque.NewMasqueAdapter(ctx, masque.AdapterConfig{
			ConfigPath:  masqueConfigPath,
			DeviceName:  "vwarp-masque",
			Endpoint:    masqueEndpoint,
			Logger:      l,
			License:     opts.License,
			NoizeConfig: noizeConfig,
		})

		if err == nil {
			l.Info("MASQUE adapter created successfully", "attempt", attempt)
			break
		}

		l.Warn("Failed to create MASQUE adapter", "attempt", attempt, "error", err)

		// On Android, sometimes network interfaces need time to stabilize
		if attempt < 3 {
			retryDelay := time.Duration(attempt) * 2 * time.Second
			l.Info("Retrying MASQUE adapter creation", "delay", retryDelay)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay):
			}
		}
	}

	if err != nil {
		return fmt.Errorf("failed to establish MASQUE connection after retries: %w", err)
	}
	defer adapter.Close()

	l.Info("MASQUE tunnel established successfully")

	// Get tunnel addresses
	ipv4, ipv6 := adapter.GetLocalAddresses()
	l.Info("MASQUE tunnel addresses", "ipv4", ipv4, "ipv6", ipv6)

	// Create TUN device configuration for the MASQUE tunnel
	tunAddresses := []netip.Addr{}
	if ipv4 != "" {
		if addr, err := netip.ParseAddr(ipv4); err == nil {
			tunAddresses = append(tunAddresses, addr)
		}
	}
	if ipv6 != "" {
		if addr, err := netip.ParseAddr(ipv6); err == nil {
			tunAddresses = append(tunAddresses, addr)
		}
	}

	if len(tunAddresses) == 0 {
		return errors.New("no valid tunnel addresses received from MASQUE")
	}

	// Use multiple DNS servers for redundancy - primary and fallbacks
	dnsServers := []netip.Addr{opts.DnsAddr}

	// Add fallback DNS servers to improve reliability
	fallbackDNS := []string{
		"8.8.8.8", // Google DNS
		"8.8.4.4", // Google DNS secondary
		"1.0.0.1", // Cloudflare DNS secondary
		"9.9.9.9", // Quad9 DNS
	}

	for _, dns := range fallbackDNS {
		if addr, err := netip.ParseAddr(dns); err == nil && addr != opts.DnsAddr {
			dnsServers = append(dnsServers, addr)
		}
	}

	l.Info("DNS servers configured", "primary", opts.DnsAddr, "fallback_count", len(dnsServers)-1)

	// Create netstack TUN
	tunDev, tnet, err := netstack.CreateNetTUN(tunAddresses, dnsServers, singleMTU)
	if err != nil {
		return fmt.Errorf("failed to create netstack: %w", err)
	}

	l.Info("netstack created on MASQUE tunnel")

	// Create adapter for the netstack device
	tunAdapter := &netstackTunAdapter{
		dev:             tunDev,
		tunnelBufPool:   &sync.Pool{New: func() interface{} { buf := make([][]byte, 1); return &buf }},
		tunnelSizesPool: &sync.Pool{New: func() interface{} { sizes := make([]int, 1); return &sizes }},
	}

	// Create adapter factory for reconnection
	adapterFactory := func() (*masque.MasqueAdapter, error) {
		l.Info("Recreating MASQUE adapter with fresh configuration")
		return masque.NewMasqueAdapter(ctx, masque.AdapterConfig{
			ConfigPath:  masqueConfigPath,
			DeviceName:  "vwarp-masque",
			Endpoint:    masqueEndpoint,
			Logger:      l,
			License:     opts.License,
			NoizeConfig: noizeConfig,
		})
	}

	// Start tunnel maintenance goroutine
	go maintainMasqueTunnel(ctx, l, adapter, adapterFactory, tunAdapter, singleMTU, tnet, opts.TestURL)

	// Test connectivity
	if err := usermodeTunTest(ctx, l, tnet, opts.TestURL); err != nil {
		l.Warn("connectivity test failed", "error", err)
		// Don't fail completely, just warn
	} else {
		l.Info("MASQUE connectivity test passed")
	}

	// Start SOCKS proxy on the netstack
	actualBind, err := wiresocks.StartProxy(ctx, l, tnet, opts.Bind)
	if err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	l.Info("serving proxy via MASQUE tunnel", "address", actualBind)

	// Keep running until context is cancelled
	<-ctx.Done()
	return nil
}

func generateWireguardConfig(i *warp.Identity) wiresocks.Configuration {
	priv, _ := wiresocks.EncodeBase64ToHex(i.PrivateKey)
	pub, _ := wiresocks.EncodeBase64ToHex(i.Config.Peers[0].PublicKey)
	clientID, _ := base64.StdEncoding.DecodeString(i.Config.ClientID)
	return wiresocks.Configuration{
		Interface: &wiresocks.InterfaceConfig{
			PrivateKey: priv,
			Addresses: []netip.Addr{
				netip.MustParseAddr(i.Config.Interface.Addresses.V4),
				netip.MustParseAddr(i.Config.Interface.Addresses.V6),
			},
		},
		Peers: []wiresocks.PeerConfig{{
			PublicKey:    pub,
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
			Endpoint: i.Config.Peers[0].Endpoint.Host,
			Reserved: [3]byte{clientID[0], clientID[1], clientID[2]},
		}},
	}
}
