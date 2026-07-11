//go:build !go1.26

package app

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/voidr3aper-anon/Vwarp/psiphon"
)

func runPsiphon(ctx context.Context, l *slog.Logger, warpBind netip.AddrPort, cacheDir string, bind netip.AddrPort, country string) error {
	return psiphon.RunPsiphon(ctx, l, warpBind, cacheDir, bind, country)
}
