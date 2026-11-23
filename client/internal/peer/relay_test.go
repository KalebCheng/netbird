package peer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/wgproxy"
)

type fakeRelayDialer struct {
	calls int
}

func (f *fakeRelayDialer) OpenConn(_ context.Context, _ string) (net.Conn, error) {
	f.calls++
	client, server := net.Pipe()
	go func() {
		_ = server.Close()
	}()
	return client, nil
}

func TestOpenRemoteConnectionForceRelaySkipsICE(t *testing.T) {
	t.Setenv("NB_FORCE_RELAY", "1")

	dialer := &fakeRelayDialer{}
	conn, err := NewConn(ConnConfig{
		Key:         "remote-peer",
		LocalKey:    "local-peer",
		RelayDialer: dialer,
		Timeout:     time.Second,
	}, nil, wgproxy.NewFactory(51820), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.ctx = context.Background()

	// conn.agent is nil: reaching the Relay dialer proves ICE was skipped.
	attempt, err := conn.openRemoteConnection(OfferAnswer{})
	if err != nil {
		t.Fatalf("openRemoteConnection: %v", err)
	}
	if !attempt.relay {
		t.Fatal("expected a relay attempt")
	}
	if dialer.calls != 1 {
		t.Fatalf("relay dial calls = %d, want 1", dialer.calls)
	}
	_ = attempt.conn.Close()
}
