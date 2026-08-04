package proxy

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"

	"github.com/fcchbjm/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupNetIP(t *testing.T) {
	resolverAddr := testDefaultUpstreamAddr
	if v := os.Getenv("DNSPROXY_TEST_RESOLVER_IP"); v != "" {
		resolverAddr = net.JoinHostPort(v, "53")
	}

	dnsUpstream, err := upstream.AddressToUpstream(
		resolverAddr,
		&upstream.Options{
			Logger:  testLogger,
			Timeout: defaultTimeout,
		},
	)
	require.NoError(t, err)

	p, err := New(&Config{
		Logger: testLogger,
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{dnsUpstream},
		},
	})
	require.NoError(t, err)

	addrs, err := p.LookupNetIP(context.Background(), "", "dns.google")
	require.NoError(t, err)
	require.NotEmpty(t, addrs)

	assert.Contains(t, addrs, netip.MustParseAddr("8.8.8.8"))
	assert.Contains(t, addrs, netip.MustParseAddr("8.8.4.4"))
	if len(addrs) > 2 {
		assert.Contains(t, addrs, netip.MustParseAddr("2001:4860:4860::8888"))
		assert.Contains(t, addrs, netip.MustParseAddr("2001:4860:4860::8844"))
	}
}

func TestLookupNetIP_usesRequestHandler(t *testing.T) {
	t.Parallel()

	const host = "lookup-handler.example."
	want := netip.MustParseAddr("10.20.30.40")

	var handlerCalls atomic.Uint32
	ups := &countingTestUpstream{}

	p := mustNew(t, &Config{
		Logger: testLogger,
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		RequestHandler: &TestHandler{
			OnHandle: func(_ context.Context, _ *Proxy, d *DNSContext) (err error) {
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
			},
		},
	})

	addrs, err := p.LookupNetIP(context.Background(), "", host)
	require.NoError(t, err)
	require.Contains(t, addrs, want)
	assert.GreaterOrEqual(t, handlerCalls.Load(), uint32(1))
	assert.Zero(t, ups.n.Load(), "Lookup must not bypass RequestHandler to upstream")
}

func TestLookupNetIP_errDrop(t *testing.T) {
	t.Parallel()

	p := mustNew(t, &Config{
		Logger: testLogger,
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{&testUpstream{}},
		},
		RequestHandler: HandlerFunc(func(
			_ context.Context,
			_ *Proxy,
			_ *DNSContext,
		) (err error) {
			return ErrDrop
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

// Exchange implements the [upstream.Upstream] interface for *countingTestUpstream.
func (u *countingTestUpstream) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	u.n.Add(1)

	return (&dns.Msg{}).SetReply(m), nil
}

// Address implements the [upstream.Upstream] interface for *countingTestUpstream.
func (u *countingTestUpstream) Address() (addr string) { return "counting-test" }

// Close implements the [upstream.Upstream] interface for *countingTestUpstream.
func (u *countingTestUpstream) Close() (err error) { return nil }
