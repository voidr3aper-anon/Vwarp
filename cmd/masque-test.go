package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/bepass-org/vwarp/masque"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	endpoint := flag.String("endpoint", os.Getenv("MASQUE_ENDPOINT"), "MASQUE server endpoint (host:port)")
	privKey := flag.String("privkey", "", "Path to ECDSA private key file (base64), or set MASQUE_PRIVKEY_B64")
	cert := flag.String("cert", "", "Path to certificate file (base64 DER), or set MASQUE_CERT_B64")
	peerPubKey := flag.String("peerpubkey", "", "Path to server public key file (PEM), or set MASQUE_PEER_PUBKEY_B64")
	skippubkeypin := flag.Bool("skip-pubkey-pinning", false, "Skip server public key pinning (sets MASQUE_SKIP_PUBKEY_PINNING=1)")
	trustFP := flag.String("trust-fp", os.Getenv("MASQUE_PEER_PUBKEY_FP"), "Expected server pubkey fingerprint (sha256 hex). Sets MASQUE_PEER_PUBKEY_FP env var")
	sni := flag.String("sni", os.Getenv("MASQUE_SNI"), "SNI for MASQUE server (default: Cloudflare)")
	connectURI := flag.String("uri", os.Getenv("MASQUE_CONNECT_URI"), "Connect-IP URI (default: Cloudflare)")
	target := flag.String("target", "162.159.198.3:443", "Target address for Connect-IP")
	resolve := flag.Bool("resolve-domain", false, "Resolve the Connect-IP host and use its resolved IP for dialing (candidate only; does not override endpoint)")
	resolveEndpoint := flag.Bool("resolve-endpoint", false, "Resolve the Connect-IP host at config time and override the explicit endpoint in the config (like masque-plus)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "Missing --endpoint or MASQUE_ENDPOINT")
		os.Exit(1)
	}

	// Optionally resolve endpoint at config-time (like masque-plus) and override --endpoint
	if *resolveEndpoint {
		// Expand the connectURI to find host
		template, err := uritemplate.New(*connectURI)
		if err == nil {
			thost, tport, _ := net.SplitHostPort(*target)
			if thost == "" {
				thost = *target
			}
			expHost := thost
			if net.ParseIP(thost) != nil && net.ParseIP(thost).To4() == nil {
				expHost = "[" + thost + "]"
			}
			expandedURI, err := template.Expand(uritemplate.Values{"target_host": uritemplate.String(expHost), "target_port": uritemplate.String(tport)})
			if err == nil {
				if u, perr := url.Parse(expandedURI); perr == nil {
					if ips, derr := net.LookupIP(u.Hostname()); derr == nil && len(ips) > 0 {
						var chosen net.IP
						// prefer v4
						for _, ip := range ips {
							if ip.To4() != nil {
								chosen = ip
								break
							}
						}
						if chosen == nil {
							chosen = ips[0]
						}
						if chosen != nil {
							// override endpoint
							*endpoint = net.JoinHostPort(chosen.String(), strconv.Itoa(443))
							logger.Info("Resolved endpoint override", "endpoint", *endpoint)
						}
					}
				}
			}
		}
	}

	// Set runtime env vars if provided before creating the client so NewClientFromFilesOrEnv picks them up
	if *skippubkeypin {
		_ = os.Setenv("MASQUE_SKIP_PUBKEY_PINNING", "1")
	}
	if *trustFP != "" {
		_ = os.Setenv("MASQUE_PEER_PUBKEY_FP", *trustFP)
	}

	client, err := masque.NewClientFromFilesOrEnv(*endpoint, *sni, *connectURI, *target, *privKey, *cert, *peerPubKey, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize MASQUE client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Set resolve behavior on client according to the flag
	client.SetResolveConnectHost(*resolve)

	// Runtime env vars were set before client creation
	udpConn, ipConn, err := client.ConnectIP(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "MASQUE ConnectIP failed: %v\n", err)
		os.Exit(2)
	}
	if udpConn != nil {
		defer udpConn.Close()
	}
	if ipConn != nil {
		defer ipConn.Close()
	}

	fmt.Println("MASQUE tunnel established successfully!")
}
