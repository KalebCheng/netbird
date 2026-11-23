//go:build windows
// +build windows

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"

	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"
)

type Win32_IP4RouteTable struct {
	Destination string
	Mask        string
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	var routes []Win32_IP4RouteTable
	query := "SELECT Destination, Mask FROM Win32_IP4RouteTable"

	err := wmi.Query(query, &routes)
	if err != nil {
		return nil, err
	}

	var prefixList []netip.Prefix
	for _, route := range routes {
		addr, err := netip.ParseAddr(route.Destination)
		if err != nil {
			continue
		}
		maskSlice := net.ParseIP(route.Mask).To4()
		if maskSlice == nil {
			continue
		}
		mask := net.IPv4Mask(maskSlice[0], maskSlice[1], maskSlice[2], maskSlice[3])
		cidr, _ := mask.Size()

		routePrefix := netip.PrefixFrom(addr, cidr)
		if routePrefix.IsValid() && routePrefix.Addr().Is4() {
			prefixList = append(prefixList, routePrefix)
		}
	}
	return prefixList, nil
}

// addToRouteTable uses the Windows route.exe syntax. The generic non-Linux
// implementation passes a CIDR to "route add", which Windows rejects.
func addToRouteTable(prefix netip.Prefix, addr string) error {
	if !prefix.Addr().Is4() {
		return fmt.Errorf("IPv6 route management is not implemented on Windows: %s", prefix)
	}

	mask := net.IP(net.CIDRMask(prefix.Bits(), 32)).String()
	cmd := exec.Command("route", "add", prefix.Addr().String(), "mask", mask, addr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add %s mask %s %s: %w: %s", prefix.Addr(), mask, addr, err, string(out))
	}
	log.Debugf("%s", out)
	return nil
}

func removeFromRouteTable(prefix netip.Prefix, _ string) error {
	if !prefix.Addr().Is4() {
		return fmt.Errorf("IPv6 route management is not implemented on Windows: %s", prefix)
	}

	mask := net.IP(net.CIDRMask(prefix.Bits(), 32)).String()
	cmd := exec.Command("route", "delete", prefix.Addr().String(), "mask", mask)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete %s mask %s: %w: %s", prefix.Addr(), mask, err, string(out))
	}
	log.Debugf("%s", out)
	return nil
}

func enableIPForwarding() error {
	log.Infof("enable IP forwarding is not implemented on Windows")
	return nil
}
