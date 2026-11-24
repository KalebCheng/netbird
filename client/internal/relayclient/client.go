package relayclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	authhmac "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	relayWebSocketPath = "/relay"

	defaultDialTimeout      = 10 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	defaultOpenConnTimeout  = 15 * time.Second
	defaultHealthCheckLimit = 40 * time.Second

	minReconnectDelay = 3 * time.Second
	maxReconnectDelay = 30 * time.Second

	maxMessageSize    = messages.MaxMessageSize
	earlyMessageLimit = 32
	connQueueSize     = 128
	peerOnlineTimeout = 10 * time.Second
	writeTimeout      = 10 * time.Second
)

var (
	ErrNotConnected = errors.New("relay connection is not established")
	ErrClosed       = errors.New("relay client is closed")
)

// Config is the Relay configuration received from Management.
type Config struct {
	URLs           []string
	TokenPayload   string
	TokenSignature string
}

// Client is a minimal Relay client compatible with the NetBird 0.81 Relay
// protocol. It keeps a single WebSocket connection to one Relay server and
// multiplexes peer connections over it.
type Client struct {
	peerID   string
	hashedID messages.PeerID
	store    *authhmac.TokenStore

	mu          sync.Mutex
	urls        []string
	tokenKey    string
	ws          *websocket.Conn
	connected   bool
	stateCh     chan struct{}
	conns       map[messages.PeerID]*Conn
	waiting     map[messages.PeerID]chan struct{}
	early       map[messages.PeerID][][]byte
	instanceURL string
	closed      bool

	writeMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	start  sync.Once

	// test hooks
	dialer *websocket.Dialer
}

// New creates a Relay client for the local peer. peerID is the local
// WireGuard public key, matching the NetBird 0.81 implementation.
func New(peerID string) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		peerID:   peerID,
		hashedID: messages.HashID(peerID),
		store:    &authhmac.TokenStore{},
		stateCh:  make(chan struct{}),
		conns:    make(map[messages.PeerID]*Conn),
		waiting:  make(map[messages.PeerID]chan struct{}),
		early:    make(map[messages.PeerID][][]byte),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// UpdateConfig replaces the Relay URLs and HMAC token. An existing connection
// is kept when only the token changes; the next reconnect uses the new token.
func (c *Client) UpdateConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("relay config is nil")
	}
	if len(cfg.URLs) == 0 {
		return errors.New("relay config has no URLs")
	}
	if cfg.TokenPayload == "" || cfg.TokenSignature == "" {
		return errors.New("relay config has no token")
	}
	if err := c.store.UpdateToken(&authhmac.Token{
		Payload:   cfg.TokenPayload,
		Signature: cfg.TokenSignature,
	}); err != nil {
		return fmt.Errorf("update relay token: %w", err)
	}

	urls := append([]string(nil), cfg.URLs...)
	key := strings.Join(urls, ",")

	c.mu.Lock()
	urlChanged := c.tokenKey != "" && c.tokenKey != key
	wasConnected := c.connected
	c.urls = urls
	c.tokenKey = key
	c.mu.Unlock()

	if urlChanged && wasConnected {
		log.Infof("relay URL changed, reconnecting")
		c.dropWebSocket()
	}
	return nil
}

// Start starts the reconnect loop. It is safe to call more than once.
func (c *Client) Start(ctx context.Context) {
	c.start.Do(func() {
		go c.run(ctx)
	})
}

// Ready reports whether the WebSocket connection is authenticated.
func (c *Client) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// ServerURL returns the Relay URL advertised in Signal offers.
func (c *Client) ServerURL() string {
	return c.firstURL()
}

func (c *Client) run(ctx context.Context) {
	delay := minReconnectDelay
	for {
		if ctx.Err() != nil || c.isClosed() {
			return
		}

		url := c.firstURL()
		if url == "" {
			if !c.wait(ctx, time.Second) {
				return
			}
			continue
		}

		ws, instanceURL, err := c.connect(ctx, url)
		if err != nil {
			if c.isClosed() || ctx.Err() != nil {
				return
			}
			log.Warnf("relay connect to %s failed: %v", url, err)
			if !c.wait(ctx, delay) {
				return
			}
			delay *= 2
			if delay > maxReconnectDelay {
				delay = maxReconnectDelay
			}
			continue
		}

		delay = minReconnectDelay
		c.setConnected(ws, instanceURL)
		log.Infof("relay connection established: url=%s instance=%s", url, instanceURL)
		c.readLoop(ws)
		c.setDisconnected(ws)
		if c.isClosed() || ctx.Err() != nil {
			return
		}
		log.Warnf("relay connection to %s lost, reconnecting", url)
		if !c.wait(ctx, minReconnectDelay) {
			return
		}
	}
}

func (c *Client) firstURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.urls) == 0 {
		return ""
	}
	// Prefer TLS URLs on 443, matching the server-side deployment.
	for _, u := range c.urls {
		if strings.HasPrefix(u, "rels://") && strings.HasSuffix(u, ":443") {
			return u
		}
	}
	for _, u := range c.urls {
		if strings.HasPrefix(u, "rels://") {
			return u
		}
	}
	return c.urls[0]
}

func (c *Client) connect(ctx context.Context, address string) (*websocket.Conn, string, error) {
	wsURL, err := prepareURL(address)
	if err != nil {
		return nil, "", err
	}

	// A direct TCP dial avoids inheriting HTTP(S)_PROXY settings on Windows.
	dialer := c.dialer
	if dialer == nil {
		dialer = &websocket.Dialer{
			HandshakeTimeout: defaultHandshakeTimeout,
			Proxy:            nil,
			NetDialContext: (&net.Dialer{
				Timeout:   defaultDialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
	}

	ws, resp, err := dialer.DialContext(ctx, wsURL, http.Header{})
	if err != nil {
		return nil, "", fmt.Errorf("websocket dial %s: %w", wsURL, err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	ws.SetReadLimit(maxMessageSize)

	authMsg, err := messages.MarshalAuthMsg(c.hashedID, c.store.TokenBinary())
	if err != nil {
		_ = ws.Close()
		return nil, "", fmt.Errorf("marshal relay auth: %w", err)
	}
	if err := c.writeWS(ws, authMsg); err != nil {
		_ = ws.Close()
		return nil, "", fmt.Errorf("write relay auth: %w", err)
	}

	_ = ws.SetReadDeadline(time.Now().Add(defaultHandshakeTimeout))
	_, data, err := ws.ReadMessage()
	if err != nil {
		_ = ws.Close()
		return nil, "", fmt.Errorf("read relay auth response: %w", err)
	}
	if _, err := messages.ValidateVersion(data); err != nil {
		_ = ws.Close()
		return nil, "", fmt.Errorf("relay auth response version: %w", err)
	}
	msgType, err := messages.DetermineServerMessageType(data)
	if err != nil {
		_ = ws.Close()
		return nil, "", fmt.Errorf("relay auth response type: %w", err)
	}
	if msgType != messages.MsgTypeAuthResponse {
		_ = ws.Close()
		return nil, "", fmt.Errorf("unexpected relay auth response type %s", msgType)
	}
	instanceURL, err := messages.UnmarshalAuthResponse(data)
	if err != nil {
		_ = ws.Close()
		return nil, "", fmt.Errorf("parse relay auth response: %w", err)
	}
	_ = ws.SetReadDeadline(time.Time{})

	return ws, instanceURL, nil
}

func (c *Client) readLoop(ws *websocket.Conn) {
	for {
		_ = ws.SetReadDeadline(time.Now().Add(defaultHealthCheckLimit))
		msgTypeRaw, data, err := ws.ReadMessage()
		if err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if !closed {
				log.Debugf("relay read loop ended: %v", err)
			}
			return
		}
		if msgTypeRaw != websocket.BinaryMessage {
			log.Warnf("relay ignored non-binary message type %d", msgTypeRaw)
			continue
		}
		if _, err := messages.ValidateVersion(data); err != nil {
			log.Warnf("relay invalid protocol version: %v", err)
			continue
		}
		msgType, err := messages.DetermineServerMessageType(data)
		if err != nil {
			log.Warnf("relay invalid message type: %v", err)
			continue
		}

		switch msgType {
		case messages.MsgTypeHealthCheck:
			if err := c.writeWS(ws, messages.MarshalHealthcheck()); err != nil {
				log.Warnf("relay health check response failed: %v", err)
				return
			}
		case messages.MsgTypeTransport:
			c.handleTransport(data)
		case messages.MsgTypePeersOnline:
			ids, err := messages.UnmarshalPeersOnlineMsg(data)
			if err != nil {
				log.Warnf("relay peers online message invalid: %v", err)
				continue
			}
			c.handlePeersOnline(ids)
		case messages.MsgTypePeersWentOffline:
			ids, err := messages.UnMarshalPeersWentOffline(data)
			if err != nil {
				log.Warnf("relay peers offline message invalid: %v", err)
				continue
			}
			c.handlePeersOffline(ids)
		case messages.MsgTypeClose:
			log.Infof("relay server closed the connection")
			return
		default:
			log.Debugf("relay ignored message type %s", msgType)
		}
	}
}

func (c *Client) handleTransport(data []byte) {
	peerID, payload, err := messages.UnmarshalTransportMsg(data)
	if err != nil {
		log.Warnf("relay transport message invalid: %v", err)
		return
	}

	c.mu.Lock()
	conn, ok := c.conns[*peerID]
	if !ok {
		c.bufferEarlyLocked(*peerID, append([]byte(nil), payload...))
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	conn.deliver(payload)
}

func (c *Client) handlePeersOnline(ids []messages.PeerID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		ch, ok := c.waiting[id]
		if !ok {
			continue
		}
		close(ch)
		delete(c.waiting, id)
	}
}

func (c *Client) handlePeersOffline(ids []messages.PeerID) {
	var closed []*Conn
	c.mu.Lock()
	for _, id := range ids {
		if conn, ok := c.conns[id]; ok {
			closed = append(closed, conn)
			delete(c.conns, id)
		}
	}
	c.mu.Unlock()
	for _, conn := range closed {
		log.Infof("relay peer went offline: %s", conn.dst.String())
		conn.closeLocal(net.ErrClosed)
	}
}

func (c *Client) bufferEarlyLocked(peerID messages.PeerID, payload []byte) {
	buf := c.early[peerID]
	if len(buf) >= earlyMessageLimit || len(payload) > maxMessageSize {
		return
	}
	c.early[peerID] = append(buf, payload)
}

// OpenConn opens a multiplexed connection to a remote peer public key. It
// waits for the Relay server to confirm that the peer is online.
func (c *Client) OpenConn(ctx context.Context, dstPeerID string) (net.Conn, error) {
	if dstPeerID == "" {
		return nil, errors.New("empty destination peer ID")
	}
	peerID := messages.HashID(dstPeerID)

	openCtx, cancel := context.WithTimeout(ctx, defaultOpenConnTimeout)
	defer cancel()

	if err := c.waitConnected(openCtx); err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if old, ok := c.conns[peerID]; ok {
		delete(c.conns, peerID)
		c.mu.Unlock()
		old.closeLocal(net.ErrClosed)
		c.mu.Lock()
	}
	conn := newConn(c, peerID)
	c.conns[peerID] = conn
	waitCh := make(chan struct{})
	c.waiting[peerID] = waitCh
	early := c.early[peerID]
	delete(c.early, peerID)
	c.mu.Unlock()

	for _, payload := range early {
		conn.deliver(payload)
	}

	if err := c.subscribePeer(peerID); err != nil {
		c.removeConn(peerID, conn)
		return nil, err
	}

	select {
	case <-waitCh:
		c.mu.Lock()
		current, stillRegistered := c.conns[peerID]
		connected := c.connected
		c.mu.Unlock()
		if !stillRegistered || current != conn || !connected {
			c.removeConn(peerID, conn)
			return nil, ErrNotConnected
		}
		return conn, nil
	case <-openCtx.Done():
		_ = c.unsubscribePeer(peerID)
		c.removeConn(peerID, conn)
		return nil, fmt.Errorf("wait for relay peer %s online: %w", peerID, openCtx.Err())
	case <-conn.done:
		c.removeConn(peerID, conn)
		return nil, net.ErrClosed
	}
}

func (c *Client) subscribePeer(peerID messages.PeerID) error {
	msgs, err := messages.MarshalSubPeerStateMsg([]messages.PeerID{peerID})
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		if err := c.write(msg); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) unsubscribePeer(peerID messages.PeerID) error {
	msgs, err := messages.MarshalUnsubPeerStateMsg([]messages.PeerID{peerID})
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		if err := c.write(msg); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) removeConn(peerID messages.PeerID, conn *Conn) {
	c.mu.Lock()
	if current, ok := c.conns[peerID]; ok && current == conn {
		delete(c.conns, peerID)
	}
	if ch, ok := c.waiting[peerID]; ok {
		close(ch)
		delete(c.waiting, peerID)
	}
	c.mu.Unlock()
	conn.closeLocal(net.ErrClosed)
}

func (c *Client) writeToPeer(peerID messages.PeerID, payload []byte) (int, error) {
	msg, err := messages.MarshalTransportMsg(peerID, payload)
	if err != nil {
		return 0, err
	}
	if err := c.write(msg); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *Client) write(msg []byte) error {
	c.mu.Lock()
	ws := c.ws
	connected := c.connected
	c.mu.Unlock()
	if !connected || ws == nil {
		return ErrNotConnected
	}
	return c.writeWS(ws, msg)
}

func (c *Client) writeWS(ws *websocket.Conn, msg []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	return ws.WriteMessage(websocket.BinaryMessage, msg)
}

func (c *Client) waitConnected(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return ErrClosed
		}
		if c.connected {
			c.mu.Unlock()
			return nil
		}
		ch := c.stateCh
		c.mu.Unlock()

		select {
		case <-ch:
		case <-ctx.Done():
			return fmt.Errorf("relay is not connected: %w", ctx.Err())
		}
	}
}

func (c *Client) wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-c.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (c *Client) setConnected(ws *websocket.Conn, instanceURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ws = ws
	c.connected = true
	c.instanceURL = instanceURL
	close(c.stateCh)
	c.stateCh = make(chan struct{})
}

func (c *Client) setDisconnected(ws *websocket.Conn) {
	c.mu.Lock()
	if c.ws != ws {
		c.mu.Unlock()
		return
	}
	c.ws = nil
	c.connected = false
	c.instanceURL = ""
	conns := make([]*Conn, 0, len(c.conns))
	for id, conn := range c.conns {
		conns = append(conns, conn)
		delete(c.conns, id)
	}
	for id, ch := range c.waiting {
		close(ch)
		delete(c.waiting, id)
	}
	c.early = make(map[messages.PeerID][][]byte)
	close(c.stateCh)
	c.stateCh = make(chan struct{})
	c.mu.Unlock()

	if !c.isClosed() {
		log.Warnf("relay disconnected, closing %d peer connections", len(conns))
	}
	for _, conn := range conns {
		conn.closeLocal(ErrNotConnected)
	}
}

func (c *Client) dropWebSocket() {
	c.mu.Lock()
	ws := c.ws
	c.mu.Unlock()
	if ws != nil {
		_ = ws.Close()
	}
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Client) localAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ws != nil {
		return c.ws.LocalAddr()
	}
	return relayAddr("relay")
}

func (c *Client) remoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.instanceURL != "" {
		return relayAddr(c.instanceURL)
	}
	if len(c.urls) > 0 {
		return relayAddr(c.urls[0])
	}
	return relayAddr("relay")
}

// Close closes the Relay connection and all multiplexed peer connections.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	ws := c.ws
	c.ws = nil
	c.connected = false
	conns := make([]*Conn, 0, len(c.conns))
	for id, conn := range c.conns {
		conns = append(conns, conn)
		delete(c.conns, id)
	}
	for id, ch := range c.waiting {
		close(ch)
		delete(c.waiting, id)
	}
	close(c.stateCh)
	c.mu.Unlock()

	c.cancel()
	if ws != nil {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		_ = ws.Close()
	}
	for _, conn := range conns {
		conn.closeLocal(net.ErrClosed)
	}
	return nil
}

func prepareURL(address string) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("parse relay address %q: %w", address, err)
	}
	switch parsed.Scheme {
	case "rel":
		parsed.Scheme = "ws"
	case "rels":
		parsed.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported relay scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("relay address %q has no host", address)
	}
	parsed.Path = relayWebSocketPath
	return parsed.String(), nil
}

type relayAddr string

func (a relayAddr) Network() string { return "relay" }
func (a relayAddr) String() string  { return string(a) }
