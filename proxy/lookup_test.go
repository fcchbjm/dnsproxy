package proxy_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/fcchbjm/dnsproxy/internal/dnsproxytest"
	"github.com/fcchbjm/dnsproxy/proxy"
	"github.com/fcchbjm/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is a common timeout for tests.
const testTimeout = 1 * time.Second

func TestProxy_LookupNetIP(t *testing.T) {
	t.Parallel()

	conf := &proxy.Config{
		Logger: testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
	}

	p := newTestProxy(t, conf)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	addrs, err := p.LookupNetIP(ctx, "", dnsproxytest.Host)
	require.NoError(t, err)
	require.NotEmpty(t, addrs)

	wantAddr := netip.AddrFrom4([4]byte(dnsproxytest.IPv4.To4()))
	assert.Contains(t, addrs, wantAddr)
}

func TestProxy_LookupNetIP_usesRequestHandler(t *testing.T) {
	t.Parallel()

	const host = "lookup-handler.example."
	want := netip.MustParseAddr("10.20.30.40")

	var handlerCalls atomic.Uint32
	ups := &countingTestUpstream{}

	p := newTestProxy(t, &proxy.Config{
		Logger: testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		RequestHandler: proxy.HandlerFunc(func(
			_ context.Context,
			_ *proxy.Proxy,
			d *proxy.DNSContext,
		) (err error) {
			handlerCalls.Add(1)
			d.Res = (&dns.Msg{}).SetReply(d.Req)
			if len(d.Req.Question) == 1 && d.Req.Question[0].Qtype == dns.TypeA {
				d.Res.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   d.Req.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: want.AsSlice(),
				}}
			}

			return nil
		}),
	})

	addrs, err := p.LookupNetIP(context.Background(), "", host)
	require.NoError(t, err)
	require.Contains(t, addrs, want)
	assert.GreaterOrEqual(t, handlerCalls.Load(), uint32(1))
	assert.Zero(t, ups.n.Load(), "Lookup must not bypass RequestHandler to upstream")
}

func TestProxy_LookupNetIP_errDrop(t *testing.T) {
	t.Parallel()

	p := newTestProxy(t, &proxy.Config{
		Logger: testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
		RequestHandler: proxy.HandlerFunc(func(
			_ context.Context,
			_ *proxy.Proxy,
			_ *proxy.DNSContext,
		) (err error) {
			return proxy.ErrDrop
		}),
	})

	addrs, err := p.LookupNetIP(context.Background(), "", "drop.example.")
	require.NoError(t, err)
	assert.Empty(t, addrs)
}

// countingTestUpstream counts Exchange calls.
type countingTestUpstream struct {
	n atomic.Uint32
}

// type check
var _ upstream.Upstream = (*countingTestUpstream)(nil)

// Exchange implements the [upstream.Upstream] interface for
// *countingTestUpstream.
func (u *countingTestUpstream) Exchange(
	_ context.Context,
	m *dns.Msg,
) (resp *dns.Msg, err error) {
	u.n.Add(1)

	return (&dns.Msg{}).SetReply(m), nil
}

// Address implements the [upstream.Upstream] interface for
// *countingTestUpstream.
func (u *countingTestUpstream) Address() (addr string) {
	return "https://" + dnsproxytest.Host
}

// Close implements the [upstream.Upstream] interface for *countingTestUpstream.
func (u *countingTestUpstream) Close() (err error) {
	return nil
}
