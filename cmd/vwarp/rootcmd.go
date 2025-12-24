package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffval"
	"github.com/voidr3aper-anon/Vwarp/app"
	"github.com/voidr3aper-anon/Vwarp/config"
	"github.com/voidr3aper-anon/Vwarp/config/noize"
	p "github.com/voidr3aper-anon/Vwarp/psiphon"
	"github.com/voidr3aper-anon/Vwarp/warp"
	"github.com/voidr3aper-anon/Vwarp/wiresocks"
)

type rootConfig struct {
	flags   *ff.FlagSet
	command *ff.Command

	verbose         bool
	v4              bool
	v6              bool
	bind            string
	endpoint        string
	key             string
	dns             string
	gool            bool
	psiphon         bool
	masque          bool
	masquePreferred bool
	country         string
	scan            bool
	rtt             time.Duration
	cacheDir        string
	fwmark          uint32
	reserved        string
	wgConf          string
	testUrl         string
	config          string

	// Unified Noize configuration
	noize       bool   // Enable noize for active protocol(s)
	noizePreset string // Unified preset for both WireGuard and MASQUE (minimal, light, medium, heavy, stealth, gfw, firewall)
	noizeExport string // Export preset to file path

	// Deprecated MASQUE Noize configuration (for backward compatibility)
	masqueNoizeConfigOld string // Deprecated: use unified config file

	// SOCKS proxy configuration
	proxyAddress string
}

func newRootCmd() *rootConfig {
	var cfg rootConfig
	cfg.flags = ff.NewFlagSet(appName)
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'v',
		LongName:  "verbose",
		Value:     ffval.NewValueDefault(&cfg.verbose, false),
		Usage:     "enable verbose logging",
		NoDefault: true,
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: '4',
		LongName:  "ipv4",
		Value:     ffval.NewValueDefault(&cfg.v4, false),
		Usage:     "only use IPv4 for random warp/MASQUE endpoint",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: '6',
		Value:     ffval.NewValueDefault(&cfg.v6, false),
		Usage:     "only use IPv6 for random warp endpoint",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'b',
		LongName:  "bind",
		Value:     ffval.NewValueDefault(&cfg.bind, "127.0.0.1:8086"),
		Usage:     "socks bind address",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'e',
		LongName:  "endpoint",
		Value:     ffval.NewValueDefault(&cfg.endpoint, ""),
		Usage:     "warp endpoint",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'k',
		LongName:  "key",
		Value:     ffval.NewValueDefault(&cfg.key, ""),
		Usage:     "warp key",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "dns",
		Value:    ffval.NewValueDefault(&cfg.dns, "1.1.1.1"),
		Usage:    "DNS address",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "gool",
		Value:    ffval.NewValueDefault(&cfg.gool, false),
		Usage:    "enable gool mode (warp in warp)",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "masque",
		Value:    ffval.NewValueDefault(&cfg.masque, false),
		Usage:    "enable MASQUE mode (connect to warp via MASQUE proxy)",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "masque-preferred",
		Value:    ffval.NewValueDefault(&cfg.masquePreferred, false),
		Usage:    "prefer MASQUE over WireGuard (with automatic fallback)",
	})
	// Unified noize configuration flags
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "noize",
		Value:    ffval.NewValueDefault(&cfg.noize, false),
		Usage:    "enable noize obfuscation for active protocol (WireGuard/MASQUE)",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "noize-preset",
		Value:    ffval.NewValueDefault(&cfg.noizePreset, "medium"),
		Usage:    "noize preset for active protocol: minimal, light, medium, heavy, stealth, gfw, firewall",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "noize-export",
		Value:    ffval.NewValueDefault(&cfg.noizeExport, ""),
		Usage:    "export preset to JSON file (e.g., --noize-export medium:config.json)",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "cfon",
		Value:    ffval.NewValueDefault(&cfg.psiphon, false),
		Usage:    "enable psiphon mode (must provide country as well)",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "country",
		Value:    ffval.NewEnum(&cfg.country, p.Countries...),
		Usage:    "psiphon country code",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "scan",
		Value:    ffval.NewValueDefault(&cfg.scan, false),
		Usage:    "enable warp scanning",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "rtt",
		Value:    ffval.NewValueDefault(&cfg.rtt, 1000*time.Millisecond),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "cache-dir",
		Value:    ffval.NewValueDefault(&cfg.cacheDir, ""),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "fwmark",
		Value:    ffval.NewValueDefault(&cfg.fwmark, 0x0),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "reserved",
		Value:    ffval.NewValueDefault(&cfg.reserved, ""),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "wgconf",
		Value:    ffval.NewValueDefault(&cfg.wgConf, ""),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "test-url",
		Value:    ffval.NewValueDefault(&cfg.testUrl, "http://connectivity.cloudflareclient.com/cdn-cgi/trace"),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'c',
		LongName:  "config",
		Value:     ffval.NewValueDefault(&cfg.config, ""),
	})

	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "proxy",
		Value:    ffval.NewValueDefault(&cfg.proxyAddress, ""),
		Usage:    "SOCKS5 proxy address to route WireGuard traffic through (e.g., socks5://127.0.0.1:1080)",
	})
	cfg.command = &ff.Command{
		Name:  appName,
		Flags: cfg.flags,
		Exec:  cfg.exec,
	}
	return &cfg
}

func (c *rootConfig) exec(ctx context.Context, args []string) error {
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if c.verbose {
		l = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// Handle noize export functionality
	if c.noizeExport != "" {
		return c.handleNoizeExport(l)
	}

	// Show deprecation warnings
	c.showDeprecationWarnings(l)

	// Load unified configuration if provided
	var unifiedConfig *config.UnifiedConfig
	if c.config != "" {
		var err error
		unifiedConfig, err = config.LoadFromFile(c.config)
		if err != nil {
			fatal(l, fmt.Errorf("failed to load config file: %w", err))
		}

		if err := unifiedConfig.Validate(); err != nil {
			fatal(l, fmt.Errorf("invalid configuration: %w", err))
		}

		// Override CLI flags with config file values
		c.applyUnifiedConfig(unifiedConfig)
		l.Info("loaded unified configuration", "file", c.config)
	}

	if c.psiphon && c.gool {
		fatal(l, errors.New("can't use cfon and gool at the same time"))
	}

	if c.masque && c.gool {
		fatal(l, errors.New("can't use masque and gool at the same time"))
	}

	if c.masque && c.psiphon {
		fatal(l, errors.New("can't use masque and cfon at the same time"))
	}

	if c.masque && c.masquePreferred {
		fatal(l, errors.New("can't use masque and masque-preferred at the same time"))
	}

	if c.masquePreferred && c.gool {
		fatal(l, errors.New("can't use masque-preferred and gool at the same time"))
	}

	if c.masquePreferred && c.psiphon {
		fatal(l, errors.New("can't use masque-preferred and cfon at the same time"))
	}

	if c.masque && c.endpoint == "" {
		// If no endpoint is provided in MASQUE mode, scan for one
		l.Info("no endpoint specified, scanning for endpoints...")
		c.scan = true
	}

	if c.v4 && c.v6 {
		fatal(l, errors.New("can't force v4 and v6 at the same time"))
	}

	if !c.v4 && !c.v6 {
		c.v4, c.v6 = true, true
	}

	bindAddrPort, err := netip.ParseAddrPort(c.bind)
	if err != nil {
		fatal(l, fmt.Errorf("invalid bind address: %w", err))
	}

	dnsAddr, err := netip.ParseAddr(c.dns)
	if err != nil {
		fatal(l, fmt.Errorf("invalid DNS address: %w", err))
	}

	opts := app.WarpOptions{
		Bind:               bindAddrPort,
		Endpoint:           c.endpoint,
		License:            c.key,
		DnsAddr:            dnsAddr,
		Gool:               c.gool,
		Masque:             c.masque,
		MasquePreferred:    c.masquePreferred,
		MasqueNoize:        c.noize && (c.masque || c.masquePreferred), // Enable if noize requested and MASQUE active
		MasqueNoizePreset:  c.noizePreset,
		MasqueNoizeConfig:  c.masqueNoizeConfigOld, // Keep old field for backward compatibility
		FwMark:             c.fwmark,
		WireguardConfig:    c.wgConf,
		Reserved:           c.reserved,
		TestURL:            c.testUrl,
		AtomicNoizeConfig:  nil, // Use unified config system instead
		ProxyAddress:       c.proxyAddress,
		UnifiedNoizeConfig: c.buildUnifiedNoizeConfig(unifiedConfig),
	}

	switch {
	case c.cacheDir != "":
		opts.CacheDir = c.cacheDir
	case xdg.CacheHome != "":
		opts.CacheDir = path.Join(xdg.CacheHome, appName)
	case os.Getenv("HOME") != "":
		opts.CacheDir = path.Join(os.Getenv("HOME"), ".cache", appName)
	default:
		opts.CacheDir = "warp_plus_cache"
	}

	if c.psiphon {
		l.Info("psiphon mode enabled", "country", c.country)
		opts.Psiphon = &app.PsiphonOptions{Country: c.country}
	}

	if c.scan {
		l.Info("scanner mode enabled", "max-rtt", c.rtt)
		opts.Scan = &wiresocks.ScanOptions{V4: c.v4, V6: c.v6, MaxRTT: c.rtt}
	}

	// If the endpoint is not set, choose a random endpoint
	if opts.Endpoint == "" {
		var addrPort netip.AddrPort
		var err error

		// Use WireGuard endpoints for both WARP and MASQUE scanning
		// MASQUE will convert port 2408 -> 443 in runWarpWithMasque
		addrPort, err = warp.RandomWarpEndpoint(c.v4, c.v6)

		if err != nil {
			fatal(l, err)
		}
		opts.Endpoint = addrPort.String()
	}

	go func() {
		if err := app.RunWarp(ctx, l, opts); err != nil {
			fatal(l, err)
		}
	}()

	<-ctx.Done()

	return nil
}

// applyUnifiedConfig applies settings from the unified config file to CLI flags
func (c *rootConfig) applyUnifiedConfig(uc *config.UnifiedConfig) {
	// Override CLI flags with config file values (config file takes precedence)
	if uc.Bind != "" && c.bind == "127.0.0.1:8086" {
		c.bind = uc.Bind
	}
	if uc.Endpoint != "" && c.endpoint == "" {
		c.endpoint = uc.Endpoint
	}
	if uc.Key != "" && c.key == "" {
		c.key = uc.Key
	}
	if uc.DNS != "" && c.dns == "1.1.1.1" {
		c.dns = uc.DNS
	}
	if uc.TestURL != "" && c.testUrl == "https://cp.cloudflare.com/" {
		c.testUrl = uc.TestURL
	}
	if uc.Proxy != "" && c.proxyAddress == "" {
		c.proxyAddress = uc.Proxy
	}

	// Set protocol modes based on config
	if uc.WireGuard != nil && uc.WireGuard.Enabled {
		if uc.WireGuard.Config != "" && c.wgConf == "" {
			c.wgConf = uc.WireGuard.Config
		}
		if uc.WireGuard.Reserved != "" && c.reserved == "" {
			c.reserved = uc.WireGuard.Reserved
		}
		if uc.WireGuard.FwMark != 0 && c.fwmark == 0 {
			c.fwmark = uc.WireGuard.FwMark
		}
	}

	if uc.MASQUE != nil && uc.MASQUE.Enabled {
		c.masque = true
		if uc.MASQUE.Preferred {
			c.masquePreferred = true
		}
	}

	if uc.Psiphon != nil && uc.Psiphon.Enabled {
		c.psiphon = true
		if uc.Psiphon.Country != "" && c.country == "" {
			c.country = uc.Psiphon.Country
		}
	}
}

// buildUnifiedNoizeConfig creates unified noize config from both CLI flags and config file
func (c *rootConfig) buildUnifiedNoizeConfig(uc *config.UnifiedConfig) *noize.UnifiedNoizeConfig {
	// Priority: Config file > CLI flags
	if uc != nil {
		// If config file has noize config, use it
		if noizeConfig, err := uc.GetNoizeConfig(); err == nil && noizeConfig != nil {
			return noizeConfig
		}
	}

	// Fall back to CLI flags if no config file or no noize in config file
	if !c.noize && c.noizePreset == "" {
		return nil
	}

	loader := noize.NewConfigLoader()

	// Handle preset-based config from CLI flags
	config, err := loader.LoadFromPreset(c.noizePreset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: invalid noize preset %s: %v\n", c.noizePreset, err)
		return nil
	}

	// Enable protocols based on active mode
	if c.masque || c.masquePreferred {
		// MASQUE mode - enable both WireGuard and MASQUE noize
		config.EnableWireGuard(c.noizePreset)
		config.EnableMASQUE(c.noizePreset)
	} else {
		// Regular WireGuard mode - enable only WireGuard noize
		config.EnableWireGuard(c.noizePreset)
	}

	return config
}

// handleNoizeExport handles the --noize-export functionality
func (c *rootConfig) handleNoizeExport(l *slog.Logger) error {
	// Parse preset:filepath format
	parts := strings.Split(c.noizeExport, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid export format, use: preset:filepath (e.g., light:config.json)")
	}

	presetName := parts[0]
	filePath := parts[1]

	loader := noize.NewConfigLoader()
	if err := loader.ExportPresetToFile(presetName, filePath); err != nil {
		return fmt.Errorf("failed to export preset: %w", err)
	}

	l.Info("exported preset configuration", "preset", presetName, "file", filePath)
	fmt.Printf("Preset '%s' exported to '%s'\n", presetName, filePath)
	fmt.Println("You can now customize the configuration and use it with --config")
	return nil
}

// showDeprecationWarnings shows warnings for deprecated CLI flags
func (c *rootConfig) showDeprecationWarnings(l *slog.Logger) {
	if c.masqueNoizeConfigOld != "" {
		l.Warn("--masque-noize-config is deprecated, use --config for unified configuration")
	}
}
