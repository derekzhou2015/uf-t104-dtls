// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// udpLoopbackProxy forwards datagrams between a DTLS client and server on UDP
// loopback, letting tests observe, drop, and inject datagrams per direction.
type udpLoopbackProxy struct {
	front      net.PacketConn // faces the DTLS client
	back       net.PacketConn // faces the DTLS server
	serverAddr net.Addr

	mu         sync.Mutex
	clientAddr net.Addr
	toServer   func([]byte) bool // false drops the datagram
	toClient   func([]byte) bool
}

func newUDPLoopbackProxy(t *testing.T, serverAddr net.Addr) *udpLoopbackProxy {
	t.Helper()
	proxy := &udpLoopbackProxy{
		front:      udpTestSocket(t),
		back:       udpTestSocket(t),
		serverAddr: serverAddr,
		toServer:   func([]byte) bool { return true },
		toClient:   func([]byte) bool { return true },
	}
	go proxy.loop(proxy.front, func(datagram []byte, addr net.Addr) {
		proxy.mu.Lock()
		proxy.clientAddr = addr
		hook := proxy.toServer
		proxy.mu.Unlock()
		if hook(datagram) {
			_, _ = proxy.back.WriteTo(datagram, proxy.serverAddr)
		}
	})
	go proxy.loop(proxy.back, func(datagram []byte, _ net.Addr) {
		proxy.mu.Lock()
		clientAddr := proxy.clientAddr
		hook := proxy.toClient
		proxy.mu.Unlock()
		if clientAddr != nil && hook(datagram) {
			_, _ = proxy.front.WriteTo(datagram, clientAddr)
		}
	})

	return proxy
}

func (p *udpLoopbackProxy) loop(socket net.PacketConn, handle func([]byte, net.Addr)) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := socket.ReadFrom(buf)
		if err != nil {
			return
		}
		handle(buf[:n], addr)
	}
}

func (p *udpLoopbackProxy) frontAddr() net.Addr { return p.front.LocalAddr() }
func (p *udpLoopbackProxy) backAddr() net.Addr  { return p.back.LocalAddr() }

func (p *udpLoopbackProxy) setHooks(toServer, toClient func([]byte) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if toServer != nil {
		p.toServer = toServer
	}
	if toClient != nil {
		p.toClient = toClient
	}
}

// injectToServer sends raw datagrams to the server from the proxy's
// server-facing address, exactly where forwarded client traffic originates.
func (p *udpLoopbackProxy) injectToServer(datagrams ...[]byte) {
	for _, datagram := range datagrams {
		_, _ = p.back.WriteTo(datagram, p.serverAddr)
	}
}

// scanDTLS12Records calls fn with the content type and epoch of every record
// header in a plaintext-header (DTLS 1.2) datagram.
func scanDTLS12Records(datagram []byte, fn func(contentType, epoch int)) {
	for len(datagram) >= 13 {
		length := int(binary.BigEndian.Uint16(datagram[11:13]))
		if len(datagram) < 13+length {
			return
		}
		fn(int(datagram[0]), int(binary.BigEndian.Uint16(datagram[3:5])))
		datagram = datagram[13+length:]
	}
}

// hasEpoch1Record reports whether a DTLS 1.2 datagram carries an epoch-1
// record. The only epoch-1 records in these tests are the Finished records
// of the final flights.
func hasEpoch1Record(datagram []byte) bool {
	found := false
	scanDTLS12Records(datagram, func(_, epoch int) {
		if epoch == 1 {
			found = true
		}
	})

	return found
}

// hasServerHello reports whether a DTLS 1.2 datagram starts an epoch-0
// handshake record with a ServerHello, marking the server's second flight.
func hasServerHello(datagram []byte) bool {
	found := false
	for len(datagram) >= 14 {
		length := int(binary.BigEndian.Uint16(datagram[11:13]))
		if len(datagram) < 13+length {
			break
		}
		if datagram[0] == byte(protocol.ContentTypeHandshake) &&
			int(binary.BigEndian.Uint16(datagram[3:5])) == 0 &&
			length >= 1 && datagram[13] == 2 { // handshake type ServerHello
			found = true
		}
		datagram = datagram[13+length:]
	}

	return found
}

// isCiphertextDatagram reports whether a datagram starts with a DTLS 1.3
// unified ciphertext header, hiding the record content type.
func isCiphertextDatagram(datagram []byte) bool {
	return len(datagram) != 0 && protocol.IsDTLS13Ciphertext(protocol.ContentType(datagram[0]))
}

func udpTestSocket(t *testing.T) net.PacketConn {
	t.Helper()
	socket, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })

	return socket
}

// startUDPPair runs a DTLS handshake across the proxy. The server listens on
// serverSocket, whose address the proxy forwards client datagrams to.
func startUDPPair(
	t *testing.T,
	proxy *udpLoopbackProxy,
	clientSocket, serverSocket net.PacketConn,
	clientOpts []ClientOption,
	serverOpts []ServerOption,
) (chan handshakeResult, chan handshakeResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	clientResult := make(chan handshakeResult, 1)
	go func() {
		client, err := Client(clientSocket, proxy.frontAddr(), clientOpts...)
		if err != nil {
			clientResult <- handshakeResult{configErr: err}

			return
		}
		t.Cleanup(func() { _ = client.Close() })
		clientResult <- handshakeResult{conn: client, handshakeError: client.HandshakeContext(ctx)}
	}()

	serverResult := make(chan handshakeResult, 1)
	go func() {
		server, err := Server(serverSocket, proxy.backAddr(), serverOpts...)
		if err != nil {
			serverResult <- handshakeResult{configErr: err}

			return
		}
		t.Cleanup(func() { _ = server.Close() })
		serverResult <- handshakeResult{conn: server, handshakeError: server.HandshakeContext(ctx)}
	}()

	return clientResult, serverResult
}

func requireHandshakeResults(t *testing.T, clientResult, serverResult chan handshakeResult) {
	t.Helper()
	for _, result := range []handshakeResult{<-clientResult, <-serverResult} {
		require.NoError(t, result.configErr)
		require.NoError(t, result.handshakeError)
	}
}

// TestDTLS12LastFlightRetransmitFreshRecordNumbers drops the server's final
// flight and lets the client retransmit its final flight with fresh record
// numbers. The server must keep recovering, but its last-flight
// retransmissions must be throttled instead of amplifying every received
// retransmission into a full flight retransmission.
func TestDTLS12LastFlightRetransmitFreshRecordNumbers(t *testing.T) {
	serverSocket := udpTestSocket(t)
	proxy := newUDPLoopbackProxy(t, serverSocket.LocalAddr())

	var clientFlight5, serverFlight6 atomic.Int64
	// Drop the server's final flight from the start so the client retransmits;
	// count both sides' final-flight datagrams.
	proxy.setHooks(
		func(datagram []byte) bool {
			if hasEpoch1Record(datagram) {
				clientFlight5.Add(1)
			}

			return true
		},
		func(datagram []byte) bool {
			if hasEpoch1Record(datagram) {
				serverFlight6.Add(1)

				return false
			}

			return true
		},
	)

	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	clientResult, serverResult := startUDPPair(t, proxy, udpTestSocket(t), serverSocket,
		[]ClientOption{
			WithInsecureSkipVerify(true),
			WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2),
			WithFlightInterval(100 * time.Millisecond), WithDisableRetransmitBackoff(true),
		},
		[]ServerOption{
			WithCertificates(certificate),
			WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2),
		},
	)

	// The client retransmits every 100ms; many retransmissions must be
	// answered by far fewer server flight retransmissions.
	require.Eventually(t, func() bool { return clientFlight5.Load() >= 10 },
		15*time.Second, 20*time.Millisecond)
	require.Eventually(t, func() bool { return serverFlight6.Load() >= 2 },
		15*time.Second, 20*time.Millisecond, "server must keep answering retransmissions")
	time.Sleep(300 * time.Millisecond)

	sends, retransmits := serverFlight6.Load(), clientFlight5.Load()
	require.GreaterOrEqual(t, retransmits, int64(10), "client must keep retransmitting its last flight")
	require.LessOrEqual(t, sends, int64(4),
		"server last-flight retransmission must be throttled, not one per received retransmission")
	require.Less(t, sends, retransmits/2, "server responses must decouple from the retransmission rate")

	// Let the next server retransmission through; the handshake must complete.
	proxy.setHooks(nil, func([]byte) bool { return true })
	requireHandshakeResults(t, clientResult, serverResult)
}

// TestDTLS12LastFlightRetransmitReusedRecordNumbers simulates a client that
// retransmits its final flight reusing record numbers, by replaying the
// captured original flight datagrams. The replay window drops them, but the
// server must still notice and retransmit its last flight (throttled) so the
// handshake can complete.
func TestDTLS12LastFlightRetransmitReusedRecordNumbers(t *testing.T) {
	serverSocket := udpTestSocket(t)
	proxy := newUDPLoopbackProxy(t, serverSocket.LocalAddr())

	var mu sync.Mutex
	var captured [][]byte
	serverHelloSeen := false
	captureComplete := false
	var serverFlight6 atomic.Int64

	// Phase 1: forward everything, capturing the client's original final
	// flight (the client datagrams following the server's ServerHello flight)
	// while dropping the server's final flight.
	proxy.setHooks(
		func(datagram []byte) bool {
			mu.Lock()
			defer mu.Unlock()
			if serverHelloSeen && !captureComplete {
				captured = append(captured, append([]byte(nil), datagram...))
				if hasEpoch1Record(datagram) {
					captureComplete = true
				}
			}

			return true
		},
		func(datagram []byte) bool {
			mu.Lock()
			if hasServerHello(datagram) {
				serverHelloSeen = true
			}
			mu.Unlock()
			if hasEpoch1Record(datagram) {
				serverFlight6.Add(1)

				return false
			}

			return true
		},
	)

	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	clientResult, serverResult := startUDPPair(t, proxy, udpTestSocket(t), serverSocket,
		[]ClientOption{
			WithInsecureSkipVerify(true),
			WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2),
			WithFlightInterval(100 * time.Millisecond),
		},
		[]ServerOption{
			WithCertificates(certificate),
			WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2),
		},
	)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()

		return captureComplete
	}, 15*time.Second, 10*time.Millisecond, "client final flight must be captured")
	mu.Lock()
	flight5 := captured
	mu.Unlock()
	require.NotEmpty(t, flight5)

	// Phase 2: drop the client's genuine retransmissions and replay the
	// captured flight with its original record numbers instead.
	proxy.setHooks(func([]byte) bool { return false }, nil)
	for range 8 {
		proxy.injectToServer(flight5...)
		time.Sleep(150 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	sends := serverFlight6.Load()
	require.GreaterOrEqual(t, sends, int64(1),
		"replayed last-flight records must trigger the server's last-flight recovery")
	require.LessOrEqual(t, sends, int64(3),
		"replay-triggered last-flight recovery must stay throttled")

	// Phase 3: forward server datagrams again and keep replaying until one
	// lands outside the throttle window and completes the handshake.
	proxy.setHooks(nil, func([]byte) bool { return true })
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(300 * time.Millisecond):
				proxy.injectToServer(flight5...)
			}
		}
	}()
	requireHandshakeResults(t, clientResult, serverResult)
}

// TestDTLS13FinalFlightRetransmitReusedRecordNumbers drops the server's ACK
// of the client's final DTLS 1.3 flight and replays the captured flight with
// its original record numbers. The replay window drops the duplicates, but
// the server must still retransmit its ACK so the client stops retransmitting.
func TestDTLS13FinalFlightRetransmitReusedRecordNumbers(t *testing.T) {
	serverSocket := udpTestSocket(t)
	proxy := newUDPLoopbackProxy(t, serverSocket.LocalAddr())

	var mu sync.Mutex
	var captured [][]byte
	var serverACKs, clientRetransmits atomic.Int64

	// Phase 1: forward everything until the client's first ciphertext
	// datagram (its final flight); capture it, then drop the server's ACKs
	// and count the client's genuine retransmissions without forwarding them.
	proxy.setHooks(
		func(datagram []byte) bool {
			if !isCiphertextDatagram(datagram) {
				return true
			}
			mu.Lock()
			first := len(captured) == 0
			if first {
				captured = append(captured, append([]byte(nil), datagram...))
			}
			mu.Unlock()
			if !first {
				clientRetransmits.Add(1)
			}

			return first // forward only the original final flight
		},
		func(datagram []byte) bool {
			if !isCiphertextDatagram(datagram) {
				return true
			}
			mu.Lock()
			seenFlight5 := len(captured) != 0
			mu.Unlock()
			if !seenFlight5 {
				return true // the server's own second flight
			}
			serverACKs.Add(1)

			return false // drop ACKs of the client's final flight
		},
	)

	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	clientResult, serverResult := startUDPPair(t, proxy, udpTestSocket(t), serverSocket,
		[]ClientOption{
			WithInsecureSkipVerify(true),
			WithMinVersion(protocol.Version1_3), WithMaxVersion(protocol.Version1_3),
			WithFlightInterval(100 * time.Millisecond), WithDisableRetransmitBackoff(true),
		},
		[]ServerOption{
			WithCertificates(certificate),
			WithMinVersion(protocol.Version1_3), WithMaxVersion(protocol.Version1_3),
		},
	)

	require.Eventually(t, func() bool { return clientRetransmits.Load() >= 2 },
		15*time.Second, 20*time.Millisecond, "client must retransmit its unacknowledged final flight")
	mu.Lock()
	flight5 := captured
	mu.Unlock()
	require.NotEmpty(t, flight5)
	initialACKs := serverACKs.Load()
	require.EqualValues(t, 1, initialACKs, "only the server's initial ACK should have been sent")

	// Phase 2: replay the captured final flight with its original record
	// numbers. The server must re-ACK even though the replay window drops
	// the duplicates.
	for range 3 {
		proxy.injectToServer(flight5...)
		time.Sleep(200 * time.Millisecond)
	}
	require.Eventually(t, func() bool { return serverACKs.Load() > initialACKs },
		5*time.Second, 20*time.Millisecond,
		"replayed final-flight records must trigger an ACK retransmission")

	// Phase 3: forward the ACK so the client stops retransmitting.
	proxy.setHooks(nil, func([]byte) bool { return true })
	proxy.injectToServer(flight5...)
	require.Eventually(t, func() bool {
		before := clientRetransmits.Load()
		time.Sleep(700 * time.Millisecond)

		return clientRetransmits.Load() == before
	}, 10*time.Second, 100*time.Millisecond, "client must stop retransmitting once its final flight is acknowledged")

	requireHandshakeResults(t, clientResult, serverResult)
}
