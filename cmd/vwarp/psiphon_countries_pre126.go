//go:build !go1.26

package main

import p "github.com/voidr3aper-anon/Vwarp/psiphon"

func supportedPsiphonCountries() []string {
	return p.Countries
}
