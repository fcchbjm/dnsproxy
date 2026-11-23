package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/fcchbjm/dnsproxy/internal/dnsproxytest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common IP address strings for tests.
const (
	testIPStr1 = "192.0.2.1"
	testIPStr2 = "192.0.2.2"
	testIPStr3 = "192.0.2.3"
)

// Common IP adresses for tests.
var (
	testIP1 = netip.MustParseAddr(testIPStr1)
	testIP2 = netip.MustParseAddr(testIPStr2)

	testRaddr = netip.AddrPortFrom(testIP1, 1234)
)

func TestRemoteAddr_direct(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		remoteAddr string
		hdr        http.Header
		wantErr    string
		wantIP     netip.AddrPort
	}{{
		name:       "no_proxy",
		remoteAddr: testRaddr.String(),
		hdr:        nil,
		wantErr:    "",
		wantIP:     testRaddr,
	}, {
		name:       "no_port",
		remoteAddr: testIPStr1,
		hdr:        nil,
		wantErr:    "not an ip:port",
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_port",
		remoteAddr: testIPStr1 + ":notport",
		hdr:        nil,
		wantErr:    `invalid port "notport" parsing "` + testIPStr1 + `:notport"`,
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_host",
		remoteAddr: "host:1",
		hdr:        nil,
		wantErr:    `ParseAddr("host"): unable to parse IP`,
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_proxied_host",
		remoteAddr: "host:1",
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr1},
		},
		wantErr: `ParseAddr("host"): unable to parse IP`,
		wantIP:  netip.AddrPort{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			subtestRemoteAddr(t, tc.remoteAddr, tc.hdr, tc.wantErr, tc.wantIP, netip.AddrPort{})
		})
	}
}

// subtestRemoteAddr makes sure that remoteAddr returns expected IP and proxy
// for given raddr and header.  header must not be nil.
func subtestRemoteAddr(
	tb testing.TB,
	raddr string,
	header http.Header,
	wantErrMsg string,
	wantIP netip.AddrPort,
	wantProxy netip.AddrPort,
) {
	r, err := http.NewRequest(http.MethodGet, dnsproxytest.Host, nil)
	require.NoError(tb, err)

	r.RemoteAddr = raddr
	r.Header = header

	var addr, prx netip.AddrPort
	addr, prx, err = remoteAddr(r, testLogger)
	if wantErrMsg != "" {
		testutil.AssertErrorMsg(tb, wantErrMsg, err)

		return
	}

	require.NoError(tb, err)
	assert.Equal(tb, wantIP, addr)
	assert.Equal(tb, wantProxy, prx)
}

func TestRemoteAddr_proxied(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		remoteAddr string
		hdr        http.Header
		wantErr    string
		wantIP     netip.AddrPort
		wantProxy  netip.AddrPort
	}{{
		name:       "proxied_with_cloudflare",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr2},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}, {
		name:       "proxied_once",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}, {
		name:       "proxied_multiple",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2 + "," + testIPStr3},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			subtestRemoteAddr(t, tc.remoteAddr, tc.hdr, tc.wantErr, tc.wantIP, tc.wantProxy)
		})
	}
}

func TestProxy_DoHMaxConcurrentRequests_unlimitedZero(t *testing.T) {
	t.Parallel()

	tlsConf, caPem := newTLSConfig(t)
	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		TLSConfig:      tlsConf,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newLocalPlainUpstreamConfig(t),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		RequestHandler: &testHandler{
			OnHandle: func(_ context.Context, _ *Proxy, d *DNSContext) (err error) {
				d.Res = replyWithTestA(d.Req)

				return nil
			},
		},
		HTTPConfig: &HTTPConfig{
			ListenAddresses:       []netip.AddrPort{dnsproxytest.LocalhostAnyPort},
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
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newLocalPlainUpstreamConfig(t),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		RequestHandler: newBlockingDoHHandler(started, release),
		HTTPConfig: &HTTPConfig{
			ListenAddresses:       []netip.AddrPort{dnsproxytest.LocalhostAnyPort},
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
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		UpstreamConfig: newLocalPlainUpstreamConfig(t),
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
		RequestHandler: newBlockingDoHHandler(started, release),
		HTTPConfig: &HTTPConfig{
			ListenAddresses:       []netip.AddrPort{dnsproxytest.LocalhostAnyPort},
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
func newBlockingDoHHandler(started, release chan struct{}) (h *testHandler) {
	var startOnce sync.Once

	return &testHandler{
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
