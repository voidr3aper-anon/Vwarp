package masque

// DefaultMasqueV4CIDRs returns the default IPv4 CIDR ranges for MASQUE endpoints
func DefaultMasqueV4CIDRs() []string {
	return []string{
		"162.159.196.0/24", // Cloudflare primary range
		"162.159.195.0/24", // Cloudflare secondary range
		"162.159.198.0/24", // Cloudflare third range
		"104.21.0.0/16",    // Cloudflare general range
		"172.67.0.0/16",    // Cloudflare proxy range
	}
}

// DefaultMasqueV6CIDRs returns the default IPv6 CIDR ranges for MASQUE endpoints
func DefaultMasqueV6CIDRs() []string {
	return []string{
		"2606:4700::/32",    // Cloudflare primary IPv6 range
		"2803:f800:50::/48", // Cloudflare alternate IPv6 range
	}
}

// DefaultMasquePort returns the default port for MASQUE connections
func DefaultMasquePort() uint16 {
	return 443 // HTTPS/QUIC port for MASQUE over HTTP/3
}

// DefaultMasqueTCPPort returns the default TCP port for HTTP/2 fallback
func DefaultMasqueTCPPort() uint16 {
	return 443 // HTTPS port for MASQUE over HTTP/2
}

// KnownMasqueEndpoints returns a list of known working MASQUE endpoints
func KnownMasqueEndpoints() []string {
	return []string{
		"162.159.198.1:443",
		"162.159.195.1:443",
		"162.159.196.1:443",
		"engage.cloudflareclient.com:443",
	}
}
