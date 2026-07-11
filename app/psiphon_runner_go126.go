//go:build go1.26

package app

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
)

func runPsiphon(ctx context.Context, l *slog.Logger, warpBind netip.AddrPort, cacheDir string, bind netip.AddrPort, country string) error {
	if l != nil {
		l.Warn("psiphon mode is disabled on Go 1.26+ due upstream psiphon-tls incompatibility")
	}
	return errors.New("psiphon mode is not supported on Go 1.26+ in this build")
}
