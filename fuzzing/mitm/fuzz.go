package self

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/testutils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const (
	alpn                        = "quic-go fuzz tests"
	rtt                         = 20 * time.Millisecond / 2
	connIDLen                   = 6 // explicitly set the connection ID length, so the proxy can parse it
	mitigationOff time.Duration = -1
	mitigationOn                = 5 * time.Second
)

var (
	proxy                  *quicproxy.QuicProxy
	serverConn, clientConn *net.UDPConn
	serverSess             quic.Session
	serverConfig           *quic.Config
	version                = protocol.SupportedVersions[0]
)

func getTLSConfig() *tls.Config {
	conf := testdata.GetTLSConfig()
	conf.NextProtos = []string{alpn}
	return conf
}

func getTLSClientConfig() *tls.Config {
	return &tls.Config{
		RootCAs:    testdata.GetRootCA(),
		NextProtos: []string{alpn},
	}
}

func setup() {
	proxy = nil
	serverConn, clientConn = nil, nil
	serverSess = nil
	serverConfig = nil

	serverConfig = &quic.Config{
		Versions:           []protocol.VersionNumber{version},
		ConnectionIDLength: connIDLen,
	}
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		panic(err)
	}
	clientConn, err = net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
}

func startServerAndProxy(delayCb quicproxy.DelayCallback, dropCb quicproxy.DropCallback) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		panic(err)
	}
	serverConn, err = net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	ln, err := quic.Listen(serverConn, getTLSConfig(), serverConfig)
	if err != nil {
		panic(err)
	}
	go func() {
		var err error
		serverSess, err = ln.Accept(context.Background())
		if err != nil {
			panic(err)
		}
		str, err := serverSess.OpenUniStream()
		if err != nil {
			panic(err)
		}
		_, err = str.Write(testserver.PRData)
		if err != nil {
			panic(err)
		}
		str.Close()
	}()
	serverPort := ln.Addr().(*net.UDPAddr).Port
	proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
		RemoteAddr:  fmt.Sprintf("localhost:%d", serverPort),
		DelayPacket: delayCb,
		DropPacket:  dropCb,
	})
	if err != nil {
		panic(err)
	}
}

func runTest(delayCb quicproxy.DelayCallback, attackTimeout time.Duration) {
	startServerAndProxy(delayCb, nil)
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
	if err != nil {
		panic(err)
	}
	sess, err := quic.Dial(
		clientConn,
		raddr,
		fmt.Sprintf("localhost:%d", proxy.LocalPort()),
		getTLSClientConfig(),
		&quic.Config{
			Versions:           []protocol.VersionNumber{version},
			ConnectionIDLength: connIDLen,
			AttackTimeout:      attackTimeout,
		},
	)
	if err != nil {
		panic(err)
	}
	str, err := sess.AcceptUniStream(context.Background())
	if err != nil {
		panic(err)
	}
	data, err := ioutil.ReadAll(str)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(data, testserver.PRData) {
		panic("data not equal to PRdata")
	}
	err = sess.Close()
	if err != nil {
		panic(err)
	}
}

func cleanup() {
	// Test shutdown is tricky due to the proxy. Just wait for a bit.
	time.Sleep(50 * time.Millisecond)
	err := clientConn.Close()
	if err != nil {
		panic(err)
	}
	err = serverConn.Close()
	if err != nil {
		panic(err)
	}
	err = proxy.Close()
	if err != nil {
		panic(err)
	}
}

// FuzzRetry injects a fuzzed Retry packet toward the client after receiving an Initial packet
// from the client.
// The fuzzed portion is the retry token
func FuzzRetry(data []byte) int {
	setup()

	sendFuzzedPacket := func(conn net.PacketConn, remoteAddr net.Addr, hdr *wire.Header) {
		retryPacket := testutils.ComposeRetryPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.DestConnectionID, data, version)
		if _, err := conn.WriteTo(retryPacket, remoteAddr); err != nil {
			panic(err)
		}
	}

	delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
		if dir == quicproxy.DirectionIncoming {
			hdr, _, _, _ := wire.ParsePacket(raw, connIDLen)
			for i := 0; i < 10; i++ {
				go sendFuzzedPacket(serverConn, clientConn.LocalAddr(), hdr)
			}
		}
		return rtt / 2
	}

	runTest(delayCb, mitigationOff)
	cleanup()

	return 1
}

// FuzzInitial injects a fuzzed Initial packet toward the client after receiving an Initial packet
// from the client.
// The fuzzed portion is the payload
func FuzzInitial(data []byte) int {
	setup()

	sendFuzzedPacket := func(conn net.PacketConn, remoteAddr net.Addr, hdr *wire.Header) {
		initialPacket := testutils.ComposeInitialByPayload(hdr.DestConnectionID, hdr.SrcConnectionID, version, hdr.DestConnectionID, data)
		if _, err := conn.WriteTo(initialPacket, remoteAddr); err != nil {
			panic(err)
		}
	}

	delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
		if dir == quicproxy.DirectionIncoming {
			hdr, _, _, _ := wire.ParsePacket(raw, connIDLen)
			for i := 0; i < 10; i++ {
				go sendFuzzedPacket(serverConn, clientConn.LocalAddr(), hdr)
			}
		}
		return rtt / 2
	}

	runTest(delayCb, mitigationOn)
	cleanup()

	return 1
}

// FuzzVN injects a fuzzed version negotiation packet toward the client after receiving an
// Initial packet.
// The fuzzed portion is the supported versions
func FuzzVN(data []byte) int {
	setup()

	sendFuzzedPacket := func(conn net.PacketConn, remoteAddr net.Addr, hdr *wire.Header) {
		vnPacket, _ := wire.ComposeVersionNegotiation(hdr.SrcConnectionID, hdr.DestConnectionID, nil)
		hdrLength := 1 /* type byte */ + 4 /* version field */ + 1 /* connection ID length field */ + hdr.SrcConnectionID.Len() + hdr.DestConnectionID.Len()
		vnPacket = append(vnPacket[:hdrLength], data...)
		if _, err := conn.WriteTo(vnPacket, remoteAddr); err != nil {
			panic(err)
		}
	}

	delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
		if dir == quicproxy.DirectionIncoming {
			hdr, _, _, _ := wire.ParsePacket(raw, connIDLen)
			for i := 0; i < 10; i++ {
				go sendFuzzedPacket(serverConn, clientConn.LocalAddr(), hdr)
			}
		}
		return rtt / 2
	}

	runTest(delayCb, mitigationOn)
	cleanup()

	return 1
}

// Fuzz runs a server and proxy and injects a random packet towards the client and server
func Fuzz(packet []byte) int {
	setup()

	sendFuzzedPacket := func(conn net.PacketConn, remoteAddr net.Addr, raw []byte) {
		if _, err := conn.WriteTo(packet, remoteAddr); err != nil {
			panic(err)
		}
	}

	delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
		if dir == quicproxy.DirectionIncoming {
			go sendFuzzedPacket(clientConn, serverConn.LocalAddr(), raw)
			go sendFuzzedPacket(serverConn, clientConn.LocalAddr(), raw)
		}
		return rtt / 2
	}

	runTest(delayCb, mitigationOn)
	cleanup()

	return 1
}
