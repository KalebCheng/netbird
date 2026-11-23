// Command relayprobe checks Relay reachability and, when a token is supplied,
// performs the NetBird 0.81 Relay authentication handshake.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	authhmac "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func main() {
	relayURL := flag.String("url", "rels://netbird.insuresmart.tech:443", "Relay URL")
	peerID := flag.String("peer-id", "relay-probe", "Peer ID used for the hashed Relay ID")
	payload := flag.String("token-payload", "", "Relay token payload from Management")
	signature := flag.String("token-signature", "", "Base64 Relay token signature from Management")
	timeout := flag.Duration("timeout", 15*time.Second, "Overall probe timeout")
	flag.Parse()

	wsURL, err := prepareURL(*relayURL)
	if err != nil {
		fail("prepare URL: %v", err)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: *timeout,
		Proxy:            nil,
		NetDialContext: (&net.Dialer{
			Timeout: *timeout,
		}).DialContext,
	}
	ws, resp, err := dialer.Dial(wsURL, http.Header{})
	if err != nil {
		fail("websocket dial %s: %v", wsURL, err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	defer ws.Close()
	fmt.Printf("OK websocket connected: %s\n", wsURL)

	hashedID := messages.HashID(*peerID)
	authPayload := []byte{}
	if *payload != "" && *signature != "" {
		store := &authhmac.TokenStore{}
		if err := store.UpdateToken(&authhmac.Token{Payload: *payload, Signature: *signature}); err != nil {
			fail("prepare token: %v", err)
		}
		authPayload = store.TokenBinary()
	}

	authMsg, err := messages.MarshalAuthMsg(hashedID, authPayload)
	if err != nil {
		fail("marshal auth: %v", err)
	}
	if err := ws.WriteMessage(websocket.BinaryMessage, authMsg); err != nil {
		fail("write auth: %v", err)
	}
	fmt.Printf("sent auth: peerID=%s token=%t\n", hashedID.String(), len(authPayload) > 0)

	_ = ws.SetReadDeadline(time.Now().Add(*timeout))
	_, data, err := ws.ReadMessage()
	if err != nil {
		fmt.Printf("AUTH NOT ACCEPTED (expected without a valid token): %v\n", err)
		return
	}
	msgType, err := messages.DetermineServerMessageType(data)
	if err != nil {
		fail("auth response type: %v", err)
	}
	if msgType != messages.MsgTypeAuthResponse {
		fail("unexpected auth response: %s", msgType)
	}
	instance, err := messages.UnmarshalAuthResponse(data)
	if err != nil {
		fail("parse auth response: %v", err)
	}
	fmt.Printf("OK relay authenticated: instance=%s\n", instance)
}

func prepareURL(address string) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "rel":
		parsed.Scheme = "ws"
	case "rels":
		parsed.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	parsed.Path = "/relay"
	return parsed.String(), nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+strings.TrimSuffix(format, "\n")+"\n", args...)
	os.Exit(1)
}
