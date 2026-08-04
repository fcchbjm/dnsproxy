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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServerDoH3Config(t *testing.T) {
	t.Parallel()

	conf := newServerDoH3Config()
	require.NotNil(t, conf)
	assert.Equal(t, int64(doh3MaxIncomingUniStreams), conf.MaxIncomingUniStreams)
	assert.NotEqual(t, int64(-1), conf.MaxIncomingUniStreams)
}

func TestHttpsProxy(t *testing.T) {
	testCases := []struct {
		name  string
		http3 bool
	}{{
		name:  "https_proxy",
		http3: false,
	}, {
		name:  "h3_proxy",
		http3: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tlsConf, caPem := newTLSConfig(t)

			httpConf := &HTTPConfig{
				ListenAddresses: []netip.AddrPort{localhostAnyPort},
				HTTP3Enabled:    tc.http3,
			}
			dnsProxy := mustNew(t, &Config{
				Logger:         testLogger,
				TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
				QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
				TLSConfig:      tlsConf,
				UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
				TrustedProxies: defaultTrustedProxies,
				HTTPConfig:     httpConf,
			})

			servicetest.RequireRun(t, dnsProxy, testTimeout)

			// Create the HTTP client that we'll be using for this test.
			client := createTestHTTPClient(dnsProxy, caPem, tc.http3)

			// Prepare a test message to be sent to the server.
			msg := newTestMessage()

			// Send the test message and check if the response is what we
			// expected.
			resp := sendTestDoHMessage(t, client, msg, nil)
			requireResponse(t, msg, resp)
		})
	}
}

func TestProxy_trustedProxies(t *testing.T) {
	var (
		clientAddr = netip.MustParseAddr("1.2.3.4")
		proxyAddr  = netip.MustParseAddr("127.0.0.1")
	)

	doRequest := func(t *testing.T, addr, expectedClientIP netip.Addr) {
		var gotAddr netip.Addr
		reqHandler := &TestHandler{
			OnHandle: func(ctx context.Context, p *Proxy, d *DNSContext) (err error) {
				gotAddr = d.Addr.Addr()

				return p.Resolve(ctx, d)
			},
		}

		// Prepare the proxy server.
		tlsConf, caPem := newTLSConfig(t)
		httpConf := &HTTPConfig{
			ListenAddresses: []netip.AddrPort{localhostAnyPort},
		}
		dnsProxy := mustNew(t, &Config{
			Logger:         testLogger,
			UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
			TrustedProxies: defaultTrustedProxies,
			RequestHandler: reqHandler,
			TLSConfig:      tlsConf,
			TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
			QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
			HTTPConfig:     httpConf,
		})

		client := createTestHTTPClient(dnsProxy, caPem, false)

		msg := newTestMessage()

		dnsProxy.TrustedProxies = netip.PrefixFrom(addr, addr.BitLen())

		servicetest.RequireRun(t, dnsProxy, testTimeout)

		hdrs := map[string]string{
			"X-Forwarded-For": strings.Join([]string{clientAddr.String(), proxyAddr.String()}, ","),
		}

		resp := sendTestDoHMessage(t, client, msg, hdrs)
		requireResponse(t, msg, resp)

		require.Equal(t, expectedClientIP, gotAddr)
	}

	t.Run("success", func(t *testing.T) {
		doRequest(t, proxyAddr, clientAddr)
	})

	t.Run("not_in_trusted", func(t *testing.T) {
		doRequest(t, netip.MustParseAddr("127.0.0.2"), proxyAddr)
	})
}

func TestAddrsFromRequest(t *testing.T) {
	var (
		theIP     = netip.AddrFrom4([4]byte{1, 2, 3, 4})
		anotherIP = netip.AddrFrom4([4]byte{1, 2, 3, 5})

		theIPStr     = theIP.String()
		anotherIPStr = anotherIP.String()
	)

	testCases := []struct {
		name    string
		hdrs    map[string]string
		wantIP  netip.Addr
		wantErr string
	}{{
		name: "cf-connecting-ip",
		hdrs: map[string]string{
			"CF-Connecting-IP": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "true-client-ip",
		hdrs: map[string]string{
			"True-Client-IP": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "x-real-ip",
		hdrs: map[string]string{
			"X-Real-IP": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "no_any",
		hdrs: map[string]string{
			"CF-Connecting-IP": "invalid",
			"True-Client-IP":   "invalid",
			"X-Real-IP":        "invalid",
		},
		wantIP:  netip.Addr{},
		wantErr: `ParseAddr(""): unable to parse IP`,
	}, {
		name: "priority",
		hdrs: map[string]string{
			"X-Forwarded-For":  strings.Join([]string{anotherIPStr, theIPStr}, ","),
			"True-Client-IP":   anotherIPStr,
			"X-Real-IP":        anotherIPStr,
			"CF-Connecting-IP": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "x-forwarded-for_simple",
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{anotherIPStr, theIPStr}, ","),
		},
		wantIP:  anotherIP,
		wantErr: "",
	}, {
		name: "x-forwarded-for_single",
		hdrs: map[string]string{
			"X-Forwarded-For": theIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "x-forwarded-for_invalid_proxy",
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{theIPStr, "invalid"}, ","),
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "x-forwarded-for_empty",
		hdrs: map[string]string{
			"X-Forwarded-For": "",
		},
		wantIP:  netip.Addr{},
		wantErr: `ParseAddr(""): unable to parse IP`,
	}, {
		name: "x-forwarded-for_redundant_spaces",
		hdrs: map[string]string{
			"X-Forwarded-For": "  " + theIPStr + "   ,\t" + anotherIPStr,
		},
		wantIP:  theIP,
		wantErr: "",
	}, {
		name: "cf-connecting-ip_redundant_spaces",
		hdrs: map[string]string{
			"CF-Connecting-IP": "  " + theIPStr + "\t",
		},
		wantIP:  theIP,
		wantErr: "",
	}}

	for _, tc := range testCases {
		r, err := http.NewRequest(http.MethodGet, "localhost", nil)
		require.NoError(t, err)

		for h, v := range tc.hdrs {
			r.Header.Set(h, v)
		}

		t.Run(tc.name, func(t *testing.T) {
			var ip netip.Addr
			ip, err = realIPFromHdrs(r)
			testutil.AssertErrorMsg(t, tc.wantErr, err)

			assert.Equal(t, tc.wantIP, ip)
		})
	}
}

func TestRemoteAddr(t *testing.T) {
	const thePort = 4321

	var (
		theIP     = netip.AddrFrom4([4]byte{1, 2, 3, 4})
		anotherIP = netip.AddrFrom4([4]byte{1, 2, 3, 5})
		thirdIP   = netip.AddrFrom4([4]byte{1, 2, 3, 6})

		theIPStr     = theIP.String()
		anotherIPStr = anotherIP.String()
		thirdIPStr   = thirdIP.String()
	)

	rAddr := netip.AddrPortFrom(theIP, thePort)

	testCases := []struct {
		name       string
		remoteAddr string
		hdrs       map[string]string
		wantErr    string
		wantIP     netip.AddrPort
		wantProxy  netip.AddrPort
	}{{
		name:       "no_proxy",
		remoteAddr: rAddr.String(),
		hdrs:       nil,
		wantErr:    "",
		wantIP:     netip.AddrPortFrom(theIP, thePort),
		wantProxy:  netip.AddrPort{},
	}, {
		name:       "proxied_with_cloudflare",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"CF-Connecting-IP": anotherIPStr,
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(anotherIP, 0),
		wantProxy: netip.AddrPortFrom(theIP, thePort),
	}, {
		name:       "proxied_once",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"X-Forwarded-For": anotherIPStr,
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(anotherIP, 0),
		wantProxy: netip.AddrPortFrom(theIP, thePort),
	}, {
		name:       "proxied_multiple",
		remoteAddr: rAddr.String(),
		hdrs: map[string]string{
			"X-Forwarded-For": strings.Join([]string{anotherIPStr, thirdIPStr}, ","),
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(anotherIP, 0),
		wantProxy: netip.AddrPortFrom(theIP, thePort),
	}, {
		name:       "no_port",
		remoteAddr: theIPStr,
		hdrs:       nil,
		wantErr:    "not an ip:port",
		wantIP:     netip.AddrPort{},
		wantProxy:  netip.AddrPort{},
	}, {
		name:       "bad_port",
		remoteAddr: theIPStr + ":notport",
		hdrs:       nil,
		wantErr:    `invalid port "notport" parsing "1.2.3.4:notport"`,
		wantIP:     netip.AddrPort{},
		wantProxy:  netip.AddrPort{},
	}, {
		name:       "bad_host",
		remoteAddr: "host:1",
		hdrs:       nil,
		wantErr:    `ParseAddr("host"): unable to parse IP`,
		wantIP:     netip.AddrPort{},
		wantProxy:  netip.AddrPort{},
	}, {
		name:       "bad_proxied_host",
		remoteAddr: "host:1",
		hdrs: map[string]string{
			"CF-Connecting-IP": theIPStr,
		},
		wantErr:   `ParseAddr("host"): unable to parse IP`,
		wantIP:    netip.AddrPort{},
		wantProxy: netip.AddrPort{},
	}}

	for _, tc := range testCases {
		r, err := http.NewRequest(http.MethodGet, "localhost", nil)
		require.NoError(t, err)

		r.RemoteAddr = tc.remoteAddr
		for h, v := range tc.hdrs {
			r.Header.Set(h, v)
		}

		t.Run(tc.name, func(t *testing.T) {
			var addr, prx netip.AddrPort
			addr, prx, err = remoteAddr(r, testLogger)
			if tc.wantErr != "" {
				testutil.AssertErrorMsg(t, tc.wantErr, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantIP, addr)
			assert.Equal(t, tc.wantProxy, prx)
		})
	}
}

// sendTestDoHMessage sends the specified DNS message using client and returns
// the DNS response.
func sendTestDoHMessage(
	t *testing.T,
	client *http.Client,
	m *dns.Msg,
	hdrs map[string]string,
) (resp *dns.Msg) {
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
func createTestHTTPClient(dnsProxy *Proxy, caPem []byte, http3Enabled bool) (client *http.Client) {
	// prepare roots list so that the server cert was successfully validated.
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

func TestProxy_DoHMaxConcurrentRequests_unlimitedZero(t *testing.T) {
	t.Parallel()

	tlsConf, caPem := newTLSConfig(t)
	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		TLSConfig:      tlsConf,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: newLocalPlainUpstreamConfig(t),
		TrustedProxies: defaultTrustedProxies,
		RequestHandler: &TestHandler{
			OnHandle: func(_ context.Context, _ *Proxy, d *DNSContext) (err error) {
				d.Res = replyWithTestA(d.Req)

				return nil
			},
		},
		HTTPConfig: &HTTPConfig{
			ListenAddresses:       []netip.AddrPort{localhostAnyPort},
			MaxConcurrentRequests: 0,
		},
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	client := createTestHTTPClient(dnsProxy, caPem, false)
	msg := newTestMessage()
	status, resp := doTestDoHRequest(t, client, msg)
	require.Equal(t, http.StatusOK, status)
	requireResponse(t, msg, resp)
}

func TestProxy_DoHMaxConcurrentRequests_rejectsWhenFull(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	tlsConf, caPem := newTLSConfig(t)
	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		TLSConfig:      tlsConf,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: newLocalPlainUpstreamConfig(t),
		TrustedProxies: defaultTrustedProxies,
		RequestHandler: newBlockingDoHHandler(started, release),
		HTTPConfig: &HTTPConfig{
			ListenAddresses:       []netip.AddrPort{localhostAnyPort},
			MaxConcurrentRequests: 1,
		},
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	client := createTestHTTPClient(dnsProxy, caPem, false)
	msg := newTestMessage()

	type dohResult struct {
		resp   *dns.Msg
		status int
		err    error
	}
	firstDone := make(chan dohResult, 1)
	go func() {
		status, resp, err := tryDoHRequest(client, msg)
		firstDone <- dohResult{status: status, resp: resp, err: err}
	}()

	waitDoHHandlerStarted(t, started)

	status, _, err := tryDoHRequest(client, newTestMessage())
	require.NoError(t, err)
	require.Equal(t, http.StatusTooManyRequests, status)

	// Hold is before newDoHReq: a request with no DNS payload must still be
	// 429 while full, not 400 Bad Request.
	emptyStatus, emptyRetry, emptyErr := tryDoHEmptyQuery(client)
	require.NoError(t, emptyErr)
	require.Equal(t, http.StatusTooManyRequests, emptyStatus)
	require.Equal(t, "1", emptyRetry)

	close(release)

	var first dohResult
	select {
	case first = <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first DoH request did not finish after release")
	}
	require.NoError(t, first.err)
	require.Equal(t, http.StatusOK, first.status)
	requireResponse(t, msg, first.resp)

	status, resp, err := tryDoHRequest(client, newTestMessage())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)

	// Slot released: empty query reaches DNS parsing and returns 400.
	emptyStatus, _, emptyErr = tryDoHEmptyQuery(client)
	require.NoError(t, emptyErr)
	require.Equal(t, http.StatusBadRequest, emptyStatus)
}

func TestProxy_DoHMaxConcurrentRequests_rejectsWhenFullBeforeBasicAuth(t *testing.T) {
	t.Parallel()

	const (
		user = "dohuser"
		pass = "dohpass"
	)

	started := make(chan struct{})
	release := make(chan struct{})
	tlsConf, caPem := newTLSConfig(t)
	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		TLSConfig:      tlsConf,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: newLocalPlainUpstreamConfig(t),
		TrustedProxies: defaultTrustedProxies,
		RequestHandler: newBlockingDoHHandler(started, release),
		HTTPConfig: &HTTPConfig{
			ListenAddresses:       []netip.AddrPort{localhostAnyPort},
			MaxConcurrentRequests: 1,
			Userinfo:              url.UserPassword(user, pass),
		},
	})
	servicetest.RequireRun(t, dnsProxy, testTimeout)

	client := createTestHTTPClient(dnsProxy, caPem, false)
	msg := newTestMessage()

	firstDone := make(chan error, 1)
	go func() {
		status, _, err := tryDoHRequestAuth(client, msg, user, pass)
		if err != nil {
			firstDone <- err

			return
		}
		if status != http.StatusOK {
			firstDone <- fmt.Errorf("first status: got %d, want %d", status, http.StatusOK)

			return
		}
		firstDone <- nil
	}()

	waitDoHHandlerStarted(t, started)

	// Hold is before BasicAuth: wrong credentials must still be 429, not 401.
	status, _, err := tryDoHRequestAuth(client, newTestMessage(), "wrong", "creds")
	require.NoError(t, err)
	require.Equal(t, http.StatusTooManyRequests, status)

	close(release)
	require.NoError(t, <-firstDone)

	// Slot released: wrong credentials reach BasicAuth and return 401.
	status, _, err = tryDoHRequestAuth(client, newTestMessage(), "wrong", "creds")
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, status)
}

// newBlockingDoHHandler returns a handler that signals started once, then blocks
// until release is closed or ctx is done, then replies with a test A record.
func newBlockingDoHHandler(started, release chan struct{}) (h *TestHandler) {
	var startOnce sync.Once

	return &TestHandler{
		OnHandle: func(ctx context.Context, _ *Proxy, d *DNSContext) (err error) {
			startOnce.Do(func() { close(started) })
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}

			d.Res = replyWithTestA(d.Req)

			return nil
		},
	}
}

// waitDoHHandlerStarted fails the test if started is not signaled in time.
func waitDoHHandlerStarted(t *testing.T, started <-chan struct{}) {
	t.Helper()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first DoH request did not enter handler")
	}
}

// replyWithTestA returns a successful reply with a single A record for tests
// that short-circuit Resolve.
func replyWithTestA(req *dns.Msg) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetReply(req)
	if len(req.Question) != 1 {
		return resp
	}

	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IPv4(8, 8, 8, 8),
	})

	return resp
}

// doTestDoHRequest sends m over DoH and returns the HTTP status and, when the
// body is a DNS message, the unpacked response.
func doTestDoHRequest(t *testing.T, client *http.Client, m *dns.Msg) (status int, resp *dns.Msg) {
	t.Helper()

	status, resp, err := tryDoHRequest(client, m)
	require.NoError(t, err)
	if status == http.StatusTooManyRequests {
		return status, nil
	}

	return status, resp
}

// tryDoHRequest is like [doTestDoHRequest] but returns an error instead of
// failing the test (safe to call from a worker goroutine).
func tryDoHRequest(client *http.Client, m *dns.Msg) (status int, resp *dns.Msg, err error) {
	packed, err := m.Pack()
	if err != nil {
		return 0, nil, err
	}

	u := url.URL{
		Scheme:   "https",
		Host:     tlsServerName,
		Path:     "/dns-query",
		RawQuery: fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(packed)),
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	httpResp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	status = httpResp.StatusCode
	if status == http.StatusTooManyRequests {
		if got := httpResp.Header.Get("Retry-After"); got != "1" {
			return status, nil, fmt.Errorf("Retry-After: got %q, want 1", got)
		}

		return status, nil, nil
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return status, nil, err
	}

	resp = &dns.Msg{}
	if err = resp.Unpack(body); err != nil {
		return status, nil, err
	}

	return status, resp, nil
}

// tryDoHRequestAuth is like [tryDoHRequest] with optional HTTP Basic credentials.
func tryDoHRequestAuth(
	client *http.Client,
	m *dns.Msg,
	user, pass string,
) (status int, resp *dns.Msg, err error) {
	packed, err := m.Pack()
	if err != nil {
		return 0, nil, err
	}

	u := url.URL{
		Scheme:   "https",
		Host:     tlsServerName,
		Path:     "/dns-query",
		RawQuery: fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(packed)),
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.SetBasicAuth(user, pass)

	httpResp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	status = httpResp.StatusCode
	if status == http.StatusTooManyRequests {
		if got := httpResp.Header.Get("Retry-After"); got != "1" {
			return status, nil, fmt.Errorf("Retry-After: got %q, want 1", got)
		}

		return status, nil, nil
	}

	if status != http.StatusOK {
		_, _ = io.Copy(io.Discard, httpResp.Body)

		return status, nil, nil
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return status, nil, err
	}

	resp = &dns.Msg{}
	if err = resp.Unpack(body); err != nil {
		return status, nil, err
	}

	return status, resp, nil
}

// tryDoHEmptyQuery GETs /dns-query with no dns= parameter (invalid for
// newDoHReq) and returns the HTTP status and Retry-After header if any.
func tryDoHEmptyQuery(client *http.Client) (status int, retryAfter string, err error) {
	u := url.URL{
		Scheme: "https",
		Host:   tlsServerName,
		Path:   "/dns-query",
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, "", err
	}

	httpResp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = httpResp.Body.Close() }()

	_, _ = io.Copy(io.Discard, httpResp.Body)

	return httpResp.StatusCode, httpResp.Header.Get("Retry-After"), nil
}
