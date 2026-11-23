package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/ice/v3"
	log "github.com/sirupsen/logrus"
)

const relayConnectTimeout = 20 * time.Second

type connAttempt struct {
	conn  net.Conn
	pair  *ice.CandidatePair
	relay bool
	err   error
}

// openRemoteConnection races an ICE dial with an optional Relay dial. ICE is
// not allowed to block the Relay fallback: both strategies run in parallel and
// the first successful transport wins.
func (conn *Conn) openRemoteConnection(remoteOfferAnswer OfferAnswer) (*connAttempt, error) {
	attemptCtx, cancel := context.WithCancel(conn.ctx)
	defer cancel()

	results := make(chan connAttempt, 2)
	attempts := 0
	forceRelay := hasForceRelay()

	if !forceRelay {
		attempts++
		go func() {
			results <- conn.dialICE(attemptCtx, remoteOfferAnswer)
		}()
	}

	if conn.config.RelayDialer != nil {
		attempts++
		go func() {
			remoteConn, err := conn.config.RelayDialer.OpenConn(attemptCtx, conn.config.Key)
			results <- connAttempt{conn: remoteConn, relay: true, err: err}
		}()
	} else if forceRelay {
		return nil, errors.New("NB_FORCE_RELAY is set but no Relay client is available")
	}

	if attempts == 0 {
		return nil, errors.New("no connection strategy available")
	}

	timeout := conn.config.Timeout
	if timeout <= 0 || timeout > relayConnectTimeout {
		timeout = relayConnectTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var firstErr error
	received := 0
	for received < attempts {
		select {
		case result := <-results:
			received++
			if result.err == nil {
				// Cancel the losing strategy and close any transport that
				// arrives after the winner.
				cancel()
				go drainAttempts(results, attempts-received)
				return &result, nil
			}
			if firstErr == nil {
				firstErr = result.err
			}
			log.Debugf("connection attempt to peer %s failed: %v", conn.config.Key, result.err)
		case <-timer.C:
			if firstErr != nil {
				return nil, fmt.Errorf("connection to peer %s timed out: %w", conn.config.Key, firstErr)
			}
			return nil, fmt.Errorf("connection to peer %s timed out", conn.config.Key)
		case <-conn.closeCh:
			return nil, NewConnectionClosedError(conn.config.Key)
		}
	}

	if firstErr == nil {
		firstErr = errors.New("all connection attempts failed")
	}
	return nil, firstErr
}

func drainAttempts(results <-chan connAttempt, n int) {
	for i := 0; i < n; i++ {
		result := <-results
		if result.conn != nil {
			_ = result.conn.Close()
		}
	}
}

func (conn *Conn) dialICE(ctx context.Context, remoteOfferAnswer OfferAnswer) connAttempt {
	// It won't release if the ICE agent went into Disconnected or Failed
	// state, so the attempt context cancels it once Relay wins.
	var remoteConn *ice.Conn
	var err error
	if conn.config.LocalKey > conn.config.Key {
		remoteConn, err = conn.agent.Dial(ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	} else {
		remoteConn, err = conn.agent.Accept(ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	}
	if err != nil {
		return connAttempt{err: err}
	}

	pair, err := conn.agent.GetSelectedCandidatePair()
	if err != nil {
		_ = remoteConn.Close()
		return connAttempt{err: err}
	}
	return connAttempt{conn: remoteConn, pair: pair}
}

// configureRelayConnection attaches the Relay stream to wgproxy and points
// WireGuard at the proxy's local UDP endpoint.
func (conn *Conn) configureRelayConnection(remoteConn net.Conn) (net.Addr, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.wgProxy = conn.wgProxyFactory.GetProxy()
	endpoint, err := conn.wgProxy.AddTurnConn(remoteConn)
	if err != nil {
		return nil, fmt.Errorf("add relay conn to wgproxy: %w", err)
	}

	endpointUDPAddr, err := net.ResolveUDPAddr(endpoint.Network(), endpoint.String())
	if err != nil {
		_ = conn.wgProxy.CloseConn()
		return nil, fmt.Errorf("resolve relay proxy endpoint %s: %w", endpoint.String(), err)
	}

	err = conn.config.WgConfig.WgInterface.UpdatePeer(
		conn.config.WgConfig.RemoteKey,
		conn.config.WgConfig.AllowedIps,
		defaultWgKeepAlive,
		endpointUDPAddr,
		conn.config.WgConfig.PreSharedKey,
	)
	if err != nil {
		_ = conn.wgProxy.CloseConn()
		return nil, fmt.Errorf("update wireguard peer for relay: %w", err)
	}

	conn.status = StatusConnected
	err = conn.statusRecorder.UpdatePeerState(State{
		PubKey:                 conn.config.Key,
		ConnStatus:             conn.status,
		ConnStatusUpdate:       time.Now(),
		Relayed:                true,
		Direct:                 false,
		LocalIceCandidateType:  "relay",
		RemoteIceCandidateType: "relay",
	})
	if err != nil {
		log.Warnf("unable to save relayed peer state: %v", err)
	}

	return endpoint, nil
}

func (conn *Conn) watchRelayConn(remoteConn net.Conn) {
	type doneConn interface {
		Done() <-chan struct{}
	}
	done, ok := remoteConn.(doneConn)
	if !ok {
		return
	}

	go func() {
		select {
		case <-done.Done():
			log.Infof("relay connection to peer %s closed", conn.config.Key)
		case <-conn.ctx.Done():
			return
		}

		conn.mu.Lock()
		notify := conn.notifyDisconnected
		conn.mu.Unlock()
		if notify != nil {
			notify()
		}
	}()
}
