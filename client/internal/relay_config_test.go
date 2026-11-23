package internal

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	mgmProto "github.com/netbirdio/netbird/management/proto"
)

func TestToRoutesCarriesDomains(t *testing.T) {
	routes := toRoutes([]*mgmProto.Route{{
		ID:      "route-1",
		NetID:   "net-1",
		Peer:    "peer-1",
		Domains: []string{"inphile.insuresmart.com.cn"},
	}})

	if len(routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(routes))
	}
	if len(routes[0].Domains) != 1 || routes[0].Domains[0] != "inphile.insuresmart.com.cn" {
		t.Fatalf("domains not preserved: %+v", routes[0].Domains)
	}
	if routes[0].Network.IsValid() {
		t.Fatalf("empty network should stay invalid for a DNS route, got %s", routes[0].Network)
	}
}

func TestCreateEngineConfigCarriesRelay(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := createEngineConfig(key, &Config{
		WgIface: "wt0",
		WgPort:  51820,
	}, &mgmProto.PeerConfig{
		Address: "100.64.0.1/16",
	}, &mgmProto.WiretrusteeConfig{
		Relay: &mgmProto.RelayConfig{
			Urls:           []string{"rels://relay.example.com:443"},
			TokenPayload:   "1700000000",
			TokenSignature: "c2lnbmF0dXJl",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relay == nil {
		t.Fatal("relay config was not carried into EngineConfig")
	}
	if cfg.Relay.URLs[0] != "rels://relay.example.com:443" ||
		cfg.Relay.TokenPayload != "1700000000" ||
		cfg.Relay.TokenSignature != "c2lnbmF0dXJl" {
		t.Fatalf("unexpected relay config: %+v", cfg.Relay)
	}
}
