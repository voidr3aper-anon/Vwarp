package main

import (
	"github.com/voidr3aper-anon/Vwarp/proxy/pkg/mixed"
)

func main() {
	proxy := mixed.NewProxy()
	_ = proxy.ListenAndServe()
}
