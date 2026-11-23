package relayclient

import (
	"net"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

// Conn implements net.Conn over a Relay transport stream.
type Conn struct {
	client *Client
	dst    messages.PeerID

	in      chan []byte
	done    chan struct{}
	once    sync.Once
	pending []byte
}

func newConn(client *Client, dst messages.PeerID) *Conn {
	return &Conn{
		client: client,
		dst:    dst,
		in:     make(chan []byte, connQueueSize),
		done:   make(chan struct{}),
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	for {
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}

		select {
		case payload := <-c.in:
			c.pending = payload
			continue
		default:
		}

		select {
		case payload := <-c.in:
			c.pending = payload
		case <-c.done:
			return 0, net.ErrClosed
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	return c.client.writeToPeer(c.dst, p)
}

func (c *Conn) Close() error {
	select {
	case <-c.done:
		return nil
	default:
	}
	_ = c.client.unsubscribePeer(c.dst)
	c.client.removeConn(c.dst, c)
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.client.localAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.client.remoteAddr() }

func (c *Conn) SetDeadline(time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// Done is closed when the connection is torn down. It lets peer.Conn observe
// Relay disconnects without polling Read.
func (c *Conn) Done() <-chan struct{} {
	return c.done
}

func (c *Conn) deliver(payload []byte) {
	select {
	case <-c.done:
		return
	default:
	}
	select {
	case c.in <- payload:
	default:
	}
}

func (c *Conn) closeLocal(err error) {
	c.once.Do(func() {
		close(c.done)
	})
}
