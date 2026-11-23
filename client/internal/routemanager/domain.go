package routemanager

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/route"
)

const (
	dnsRouteIntervalEnv     = "NB_DNS_ROUTE_INTERVAL"
	defaultDNSRouteInterval = time.Minute
	minDNSRouteInterval     = 10 * time.Second
	dnsLookupTimeout        = 5 * time.Second
)

// domainRouteResolver expands Route.Domains into host prefixes. The 0.25
// route manager only understands CIDRs, so this is a minimal compatibility
// layer rather than the 0.81 dynamic-route architecture.
type domainRouteResolver struct {
	base     []*route.Route
	routes   map[string]*route.Route
	resolved map[string]map[string]netip.Prefix
	lookup   func(ctx context.Context, domain string) (netip.Prefix, error)
}

func newDomainRouteResolver() *domainRouteResolver {
	return &domainRouteResolver{
		routes:   make(map[string]*route.Route),
		resolved: make(map[string]map[string]netip.Prefix),
		lookup:   lookupSingleHostPrefix,
	}
}

func (r *domainRouteResolver) hasRoutes() bool {
	return len(r.routes) > 0
}

func (r *domainRouteResolver) setBaseRoutes(routes []*route.Route) {
	r.base = routes

	newRoutes := make(map[string]*route.Route)
	newResolved := make(map[string]map[string]netip.Prefix)
	for _, rt := range routes {
		if len(rt.Domains) == 0 {
			continue
		}
		newRoutes[rt.ID] = rt
		if old, ok := r.resolved[rt.ID]; ok {
			newResolved[rt.ID] = old
		} else {
			newResolved[rt.ID] = make(map[string]netip.Prefix)
		}
	}
	r.routes = newRoutes
	r.resolved = newResolved
}

// resolve returns the expanded route list and whether any resolved prefix
// changed. Lookup failures keep the previous prefix to avoid route flapping.
func (r *domainRouteResolver) resolve(ctx context.Context) ([]*route.Route, bool) {
	changed := false

	for id, rt := range r.routes {
		current := r.resolved[id]
		activeDomains := make(map[string]struct{}, len(rt.Domains))
		for _, domain := range rt.Domains {
			activeDomains[domain] = struct{}{}
			prefix, err := r.lookup(ctx, domain)
			if err != nil {
				log.Warnf("failed to resolve DNS route domain %s: %v", domain, err)
				continue
			}
			old, ok := current[domain]
			if !ok || old != prefix {
				current[domain] = prefix
				changed = true
				log.Infof("DNS route %s resolved %s -> %s", id, domain, prefix)
			}
		}
		for domain := range current {
			if _, ok := activeDomains[domain]; !ok {
				delete(current, domain)
				changed = true
			}
		}
	}

	expanded := make([]*route.Route, 0, len(r.base))
	for _, rt := range r.base {
		if len(rt.Domains) == 0 {
			expanded = append(expanded, rt)
			continue
		}

		seen := make(map[netip.Prefix]struct{})
		for _, domain := range rt.Domains {
			prefix, ok := r.resolved[rt.ID][domain]
			if !ok {
				continue
			}
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			expanded = append(expanded, expandDomainRoute(rt, prefix))
		}
	}

	return expanded, changed
}

func expandDomainRoute(base *route.Route, prefix netip.Prefix) *route.Route {
	networkType := route.IPv4Network
	if prefix.Addr().Is6() {
		networkType = route.IPv6Network
	}
	return &route.Route{
		ID:          fmt.Sprintf("%s-dns-%s", base.ID, prefix),
		Network:     prefix,
		NetID:       base.NetID,
		NetworkType: networkType,
		Peer:        base.Peer,
		Metric:      base.Metric,
		Masquerade:  base.Masquerade,
		Enabled:     base.Enabled,
	}
}

func lookupSingleHostPrefix(ctx context.Context, domain string) (netip.Prefix, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(lookupCtx, domain)
	if err != nil {
		return netip.Prefix{}, err
	}
	if len(ips) == 0 {
		return netip.Prefix{}, fmt.Errorf("no A/AAAA record")
	}

	// Minimal PoC: use one address, preferring IPv4.
	var chosen netip.Addr
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			chosen = addr
			break
		}
		if !chosen.IsValid() {
			chosen = addr
		}
	}
	if !chosen.IsValid() {
		return netip.Prefix{}, fmt.Errorf("no usable A/AAAA record")
	}
	return netip.PrefixFrom(chosen, chosen.BitLen()), nil
}

func domainRouteInterval() time.Duration {
	value := os.Getenv(dnsRouteIntervalEnv)
	if value == "" {
		return defaultDNSRouteInterval
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		log.Warnf("invalid %s=%q, using default %s", dnsRouteIntervalEnv, value, defaultDNSRouteInterval)
		return defaultDNSRouteInterval
	}
	interval := time.Duration(seconds) * time.Second
	if interval < minDNSRouteInterval {
		interval = minDNSRouteInterval
	}
	return interval
}
