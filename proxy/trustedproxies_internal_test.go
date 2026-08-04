package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProxy_TrustedProxies_nilNormalized checks that New turns a nil
// TrustedProxies into an empty fail-closed set so Contains never panics.
func TestProxy_TrustedProxies_nilNormalized(t *testing.T) {
	t.Parallel()

	p := mustNew(t, &Config{
		Logger:         testLogger,
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies: nil,
	})

	require.NotNil(t, p.TrustedProxies)
	require.NotPanics(t, func() {
		assert.False(t, p.TrustedProxies.Contains(netip.MustParseAddr("127.0.0.1")))
		assert.False(t, p.TrustedProxies.Contains(netip.MustParseAddr("8.8.8.8")))
		assert.False(t, p.TrustedProxies.Contains(netip.MustParseAddr("::1")))
	})
}

// TestProxy_TrustedProxies_nilDoHIgnoresForwardingHeaders exercises the DoH
// ServeHTTP path with nil TrustedProxies at New: forwarding headers must not
// panic, must not be trusted, and the query must still get a reply using the
// direct peer address.  CF and XFF are separate cases because realIPFromHdrs
// prefers CF-Connecting-IP over X-Forwarded-For.
func TestProxy_TrustedProxies_nilDoHIgnoresForwardingHeaders(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		hdrs map[string]string
		want netip.Addr
	}{{
		name: "cf_connecting_ip",
		hdrs: map[string]string{
			"CF-Connecting-IP": "9.9.9.9",
		},
		want: netip.MustParseAddr("9.9.9.9"),
	}, {
		name: "x_forwarded_for",
		hdrs: map[string]string{
			"X-Forwarded-For": "1.2.3.4,127.0.0.1",
		},
		want: netip.MustParseAddr("1.2.3.4"),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotAddr netip.Addr

			tlsConf, caPem := newTLSConfig(t)
			dnsProxy := mustNew(t, &Config{
				Logger:         testLogger,
				TLSConfig:      tlsConf,
				TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
				UpstreamConfig: newLocalPlainUpstreamConfig(t),
				TrustedProxies: nil,
				RequestHandler: &TestHandler{
					OnHandle: func(_ context.Context, _ *Proxy, d *DNSContext) (err error) {
						gotAddr = d.Addr.Addr()
						d.Res = replyWithTestA(d.Req)

						return nil
					},
				},
				HTTPConfig: &HTTPConfig{
					ListenAddresses: []netip.AddrPort{localhostAnyPort},
				},
			})
			require.NotNil(t, dnsProxy.TrustedProxies)
			require.False(t, dnsProxy.TrustedProxies.Contains(tc.want))

			servicetest.RequireRun(t, dnsProxy, testTimeout)

			client := createTestHTTPClient(dnsProxy, caPem, false)
			msg := newTestMessage()

			require.NotPanics(t, func() {
				resp := sendTestDoHMessage(t, client, msg, tc.hdrs)
				requireResponse(t, msg, resp)
			})

			require.True(t, gotAddr.IsValid(), "handler must observe a client address")
			assert.NotEqual(t, tc.want, gotAddr, "forwarding header must not be trusted")
			assert.True(t, gotAddr.IsLoopback(), "expected direct peer (loopback test client), got %s", gotAddr)
		})
	}
}
