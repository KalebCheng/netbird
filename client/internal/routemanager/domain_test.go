package routemanager

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/route"
)

func TestDomainRouteResolverExpandsToHostPrefix(t *testing.T) {
	resolver := newDomainRouteResolver()
	resolver.lookup = func(_ context.Context, domain string) (netip.Prefix, error) {
		switch domain {
		case "inphile.insuresmart.com.cn":
			return netip.MustParsePrefix("172.19.17.11/32"), nil
		case "alias.insuresmart.com.cn":
			return netip.MustParsePrefix("172.19.17.11/32"), nil
		default:
			return netip.Prefix{}, errors.New("not found")
		}
	}

	static := &route.Route{ID: "static", Network: netip.MustParsePrefix("10.0.0.0/24"), Peer: "peer-a", NetID: "net-a"}
	domainRoute := &route.Route{
		ID:      "dns-route",
		Peer:    "peer-a",
		NetID:   "net-a",
		Metric:  1,
		Domains: []string{"inphile.insuresmart.com.cn", "alias.insuresmart.com.cn"},
	}
	resolver.setBaseRoutes([]*route.Route{static, domainRoute})

	expanded, changed := resolver.resolve(context.Background())
	if !changed {
		t.Fatal("expected initial resolution to report a change")
	}
	if len(expanded) != 2 {
		t.Fatalf("expanded routes = %d, want 2: %+v", len(expanded), expanded)
	}
	if expanded[0] != static {
		t.Fatalf("static route was not preserved: %+v", expanded[0])
	}
	if expanded[1].Network.String() != "172.19.17.11/32" {
		t.Fatalf("resolved network = %s, want 172.19.17.11/32", expanded[1].Network)
	}

	_, changed = resolver.resolve(context.Background())
	if changed {
		t.Fatal("expected unchanged resolution to report no change")
	}
}

func TestDomainRouteResolverKeepsPreviousPrefixOnLookupError(t *testing.T) {
	resolver := newDomainRouteResolver()
	fail := false
	resolver.lookup = func(_ context.Context, _ string) (netip.Prefix, error) {
		if fail {
			return netip.Prefix{}, errors.New("temporary failure")
		}
		return netip.MustParsePrefix("192.0.2.10/32"), nil
	}
	resolver.setBaseRoutes([]*route.Route{{
		ID:      "dns-route",
		Peer:    "peer-a",
		NetID:   "net-a",
		Domains: []string{"example.test"},
	}})

	expanded, _ := resolver.resolve(context.Background())
	if len(expanded) != 1 || expanded[0].Network.String() != "192.0.2.10/32" {
		t.Fatalf("unexpected initial expansion: %+v", expanded)
	}

	fail = true
	expanded, changed := resolver.resolve(context.Background())
	if changed {
		t.Fatal("lookup failure must not flap the route")
	}
	if len(expanded) != 1 || expanded[0].Network.String() != "192.0.2.10/32" {
		t.Fatalf("previous prefix was not retained: %+v", expanded)
	}
}
