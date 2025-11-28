package app

import (
	"context"
	"log/slog"
	"sync"

	"github.com/bepass-org/vwarp/masque"
	"github.com/bepass-org/vwarp/wireguard/tun"
)

// netstackTunAdapter wraps a tun.Device to provide ReadPacket/WritePacket interface
// Compatible with usque's tunnel maintenance approach
type netstackTunAdapter struct {
	dev             tun.Device
	tunnelBufPool   *sync.Pool
	tunnelSizesPool *sync.Pool
}

func (n *netstackTunAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *netstackTunAdapter) WritePacket(pkt []byte) error {
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// maintainMasqueTunnel continuously forwards packets between the TUN device and MASQUE
// Based on usque's MaintainTunnel function
func maintainMasqueTunnel(ctx context.Context, l *slog.Logger, client *masque.MasqueClient, device *netstackTunAdapter, mtu int) {
	l.Info("Starting MASQUE tunnel packet forwarding")

	// Forward packets from netstack to MASQUE
	go func() {
		buf := make([]byte, mtu)
		packetCount := 0
		for ctx.Err() == nil {
			n, err := device.ReadPacket(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				l.Error("error reading from TUN device", "error", err)
				continue
			}

			packetCount++
			if packetCount <= 5 || packetCount%100 == 0 {
				l.Info("TX netstack→MASQUE", "packet", packetCount, "bytes", n)
			}

			// Write packet to MASQUE and handle ICMP response
			icmp, err := client.WriteWithICMP(buf[:n])
			if err != nil {
				l.Error("error writing to MASQUE", "error", err, "packet_size", n)
				continue
			}

			// Handle ICMP response if present
			if len(icmp) > 0 {
				l.Warn("received ICMP response", "size", len(icmp))
				if err := device.WritePacket(icmp); err != nil {
					l.Error("error writing ICMP to TUN device", "error", err)
				}
			}
		}
	}()

	// Forward packets from MASQUE to netstack
	go func() {
		buf := make([]byte, mtu)
		packetCount := 0
		for ctx.Err() == nil {
			n, err := client.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				l.Error("error reading from MASQUE", "error", err)
				continue
			}

			packetCount++
			if packetCount <= 5 || packetCount%100 == 0 {
				l.Info("RX MASQUE→netstack", "packet", packetCount, "bytes", n)
			}

			if err := device.WritePacket(buf[:n]); err != nil {
				l.Error("error writing to TUN device", "error", err, "packet_size", n)
			}
		}
	}()
}
