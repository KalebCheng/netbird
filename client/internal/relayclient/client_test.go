package relayclient

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func TestPrepareURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"rels://relay.example.com:443", "wss://relay.example.com:443/relay"},
		{"rel://relay.example.com:80", "ws://relay.example.com:80/relay"},
		{"rels://relay.example.com", "wss://relay.example.com/relay"},
	}
	for _, tt := range tests {
		got, err := prepareURL(tt.in)
		if err != nil {
			t.Fatalf("prepareURL(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("prepareURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if _, err := prepareURL("https://relay.example.com"); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}

func TestClientHandshakeAndTransport(t *testing.T) {
	const (
		localPeer  = "local-public-key"
		remotePeer = "remote-public-key"
		secret     = "relay-test-secret"
	)

	localID := messages.HashID(localPeer)
	remoteID := messages.HashID(remotePeer)

	generator, err := v2.NewGenerator(v2.AuthAlgoHMACSHA256, []byte(secret), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, err := generator.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	healthChecked := make(chan struct{})
	var healthOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer ws.Close()

		_, authData, err := ws.ReadMessage()
		if err != nil {
			t.Errorf("read auth: %v", err)
			return
		}
		peerID, payload, err := messages.UnmarshalAuthMsg(authData)
		if err != nil {
			t.Errorf("unmarshal auth: %v", err)
			return
		}
		if *peerID != localID {
			t.Errorf("auth peer ID = %s, want %s", peerID.String(), localID.String())
			return
		}
		if err := v2.NewValidator([]byte(secret)).Validate(payload); err != nil {
			t.Errorf("validate auth payload: %v", err)
			return
		}
		authResp, err := messages.MarshalAuthResponse("rel://test-relay")
		if err != nil {
			t.Errorf("marshal auth response: %v", err)
			return
		}
		if err := ws.WriteMessage(websocket.BinaryMessage, authResp); err != nil {
			t.Errorf("write auth response: %v", err)
			return
		}
		if err := ws.WriteMessage(websocket.BinaryMessage, messages.MarshalHealthcheck()); err != nil {
			t.Errorf("write health check: %v", err)
			return
		}

		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			msgType, err := messages.DetermineClientMessageType(data)
			if err != nil {
				t.Errorf("client message type: %v", err)
				return
			}
			switch msgType {
			case messages.MsgTypeSubscribePeerState:
				ids, err := messages.UnmarshalSubPeerStateMsg(data)
				if err != nil || len(ids) != 1 || ids[0] != remoteID {
					t.Errorf("subscribe message invalid: ids=%v err=%v", ids, err)
					return
				}
				online, _ := messages.MarshalPeersOnline([]messages.PeerID{remoteID})
				for _, msg := range online {
					_ = ws.WriteMessage(websocket.BinaryMessage, msg)
				}
			case messages.MsgTypeHealthCheck:
				healthOnce.Do(func() { close(healthChecked) })
			case messages.MsgTypeTransport:
				id, payload, err := messages.UnmarshalTransportMsg(data)
				if err != nil {
					t.Errorf("unmarshal transport: %v", err)
					return
				}
				if *id != remoteID {
					t.Errorf("transport destination = %s, want %s", id.String(), remoteID.String())
					return
				}
				// The relay server rewrites the source ID to the sending peer.
				echo, _ := messages.MarshalTransportMsg(remoteID, payload)
				_ = ws.WriteMessage(websocket.BinaryMessage, echo)
			case messages.MsgTypeUnsubscribePeerState:
			}
		}
	}))
	defer server.Close()

	relayURL := "rel://" + strings.TrimPrefix(server.URL, "http://")
	client := New(localPeer)
	if err := client.UpdateConfig(&Config{
		URLs:           []string{relayURL},
		TokenPayload:   string(token.Payload),
		TokenSignature: base64.StdEncoding.EncodeToString(token.Signature),
	}); err != nil {
		t.Fatal(err)
	}
	client.Start(context.Background())
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waitReady(t, ctx, client)

	conn, err := client.OpenConn(ctx, remotePeer)
	if err != nil {
		t.Fatalf("open conn: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello relay")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello relay" {
		t.Fatalf("echo = %q", string(buf[:n]))
	}

	if _, ok := conn.(interface{ Done() <-chan struct{} }); !ok {
		t.Fatal("relay conn does not expose Done")
	}
	select {
	case <-healthChecked:
	case <-time.After(2 * time.Second):
		t.Fatal("relay client did not answer the health check")
	}
}

func waitReady(t *testing.T, ctx context.Context, client *Client) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if client.Ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("relay client did not become ready")
		case <-ticker.C:
		}
	}
}
