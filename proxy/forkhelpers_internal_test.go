package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/fcchbjm/dnsproxy/internal/dnsproxytest"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

// tlsServerName is the server name used by test TLS certificates.
const tlsServerName = dnsproxytest.TLSServerName

// testMessagesCount is the number of messages sent by sendTestMessages.
const testMessagesCount = 10

// sendTestMessages sends [testMessagesCount] DNS requests to the specified
// connection and checks the responses.
func sendTestMessages(tb testing.TB, conn *dns.Conn) {
	tb.Helper()

	for i := range testMessagesCount {
		req := newTestMessage()
		err := conn.WriteMsg(req)
		require.NoErrorf(tb, err, "req number %d", i)

		res, err := conn.ReadMsg()
		require.NoErrorf(tb, err, "resp number %d", i)

		requireResponse(tb, req, res)
	}
}

// mustStartDefaultProxy starts a new proxy with default settings and returns
// it.  It fails the test on error.
func mustStartDefaultProxy(tb testing.TB) (p *Proxy) {
	tb.Helper()

	p = mustNew(tb, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfigFromAddrs(tb, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})

	servicetest.RequireRun(tb, p, testTimeout)

	return p
}

// newLocalUpstreamListener creates a new localhost listener on the specified
// port for tcp4 network and returns its listening address.
func newLocalUpstreamListener(
	tb testing.TB,
	port uint16,
	h dns.Handler,
) (real netip.AddrPort) {
	tb.Helper()

	startCh := make(chan struct{})
	upsSrv := &dns.Server{
		Addr:              netip.AddrPortFrom(netutil.IPv4Localhost(), port).String(),
		Net:               "tcp",
		Handler:           h,
		NotifyStartedFunc: func() { close(startCh) },
	}
	go func() {
		err := upsSrv.ListenAndServe()
		require.NoError(testutil.PanicT{}, err)
	}()

	<-startCh
	testutil.CleanupAndRequireSuccess(tb, upsSrv.Shutdown)

	return testutil.RequireTypeAssert[*net.TCPAddr](tb, upsSrv.Listener.Addr()).AddrPort()
}

// newTLSConfig returns a fresh TLS config and its PEM-encoded certificate for
// tests.
func newTLSConfig(tb testing.TB) (conf *tls.Config, certPem []byte) {
	tb.Helper()

	return dnsproxytest.NewTLSConfig(tb)
}

// newTestMessage returns a common DNS request for tests.
func newTestMessage() (req *dns.Msg) {
	return newHostTestMessage("google-public-dns-a.google.com")
}

// newHostTestMessage returns a DNS request for host.
func newHostTestMessage(host string) (req *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   host + ".",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

// requireResponse ensures that reply matches req and contains the A record
// with 8.8.8.8.
func requireResponse(tb testing.TB, req, reply *dns.Msg) {
	tb.Helper()

	require.NotNil(tb, reply)
	require.Lenf(tb, reply.Answer, 1, "wrong number of answers: %d", len(reply.Answer))
	require.Equal(tb, req.Id, reply.Id)

	a := testutil.RequireTypeAssert[*dns.A](tb, reply.Answer[0])

	require.Equalf(tb, net.IPv4(8, 8, 8, 8), a.A.To16(), "wrong answer: %v", a.A)
}

// sendTestDoHMessage sends the specified DNS message using client and returns
// the DNS response.
func sendTestDoHMessage(
	t *testing.T,
	client *http.Client,
	m *dns.Msg,
	hdrs map[string]string,
) (resp *dns.Msg) {
	t.Helper()

	packed, err := m.Pack()
	require.NoError(t, err)

	u := url.URL{
		Scheme:   "https",
		Host:     tlsServerName,
		Path:     "/dns-query",
		RawQuery: fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(packed)),
	}

	method := http.MethodGet
	if _, ok := client.Transport.(*http3.Transport); ok {
		// If we're using HTTP/3, use http3.MethodGet0RTT to force using 0-RTT.
		method = http3.MethodGet0RTT
	}

	req, err := http.NewRequest(method, u.String(), nil)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	for k, v := range hdrs {
		req.Header.Set(k, v)
	}

	httpResp, err := client.Do(req) // nolint:bodyclose
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, httpResp.Body.Close)

	require.True(
		t,
		httpResp.ProtoAtLeast(2, 0),
		"the proto is too old: %s",
		httpResp.Proto,
	)

	body, err := io.ReadAll(httpResp.Body)
	require.NoError(t, err)

	resp = &dns.Msg{}
	err = resp.Unpack(body)
	require.NoError(t, err)

	return resp
}

// createTestHTTPClient creates an *http.Client that will be used to send
// requests to the specified dnsProxy.
func createTestHTTPClient(
	dnsProxy *Proxy,
	caPem []byte,
	http3Enabled bool,
) (client *http.Client) {
	// Prepare roots list so that the server cert was successfully validated.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsClientConfig := &tls.Config{
		ServerName: tlsServerName,
		RootCAs:    roots,
	}

	var transport http.RoundTripper

	if http3Enabled {
		tlsClientConfig.NextProtos = []string{"h3"}

		transport = &http3.Transport{
			Dial: func(
				ctx context.Context,
				_ string,
				tlsCfg *tls.Config,
				cfg *quic.Config,
			) (*quic.Conn, error) {
				addr := dnsProxy.Addr(ProtoHTTPS).String()

				return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
			},
			TLSClientConfig:    tlsClientConfig,
			QUICConfig:         &quic.Config{},
			DisableCompression: true,
		}
	} else {
		dialer := &net.Dialer{
			Timeout: defaultTimeout,
		}
		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Route request to the DNS-over-HTTPS server address.
			return dialer.DialContext(ctx, network, dnsProxy.Addr(ProtoHTTPS).String())
		}

		tlsClientConfig.NextProtos = []string{"h2", "http/1.1"}
		transport = &http.Transport{
			TLSClientConfig:    tlsClientConfig,
			DisableCompression: true,
			DialContext:        dialContext,
			ForceAttemptHTTP2:  true,
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   defaultTimeout,
	}
}

// mustNew creates a new proxy or fails the test.  Fork-only tests predate the
// upstream newTestProxy helper and keep using this name.
func mustNew(tb testing.TB, conf *Config) (p *Proxy) {
	tb.Helper()

	return newTestProxy(tb, conf)
}
