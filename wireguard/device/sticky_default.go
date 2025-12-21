//go:build !linux

package device

import (
	"github.com/voidr3aper-anon/Vwarp/wireguard/conn"
	"github.com/voidr3aper-anon/Vwarp/wireguard/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
