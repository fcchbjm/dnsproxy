package proxy_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/fcchbjm/dnsproxy/internal/dnsmsg"
	"github.com/fcchbjm/dnsproxy/internal/middleware"
	"github.com/fcchbjm/dnsproxy/proxy"
	"github.com/fcchbjm/dnsproxy/ratelimit"
	"github.com/fcchbjm/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLookupNetIP_hostsMiddleware checks that LookupNetIP uses the same
// RequestHandler path as inbound queries, including hosts-file middleware.
func TestLookupNetIP_hostsMiddleware(t *testing.T) {
	t.Parallel()

	const host = "lookup-hosts.example"
	want := netip.MustParseAddr("192.0.2.55")

	hostsPath := filepath.Join(t.TempDir(), "hosts")
	// Hosts-file names are stored without a trailing dot.
	require.NoError(t, os.WriteFile(
		hostsPath,
		[]byte(want.String()+" "+host+"\n"),
		0o600,
	))

	ctx := context.Background()
	logger := slogutil.NewDiscardLogger()
	strg, err := middleware.ReadHosts(ctx, logger, []string{hostsPath})
	require.NoError(t, err)

	preMw := middleware.New(&middleware.Config{
		Logger:             logger,
		MessageConstructor: dnsmsg.DefaultMessageConstructor{},
		HostsFiles:         strg,
		// Avoid AAAA falling through to upstream when hosts only has A.
		HaltIPv6: true,
	})

	ups := &countingUpstream{}
	p, err := proxy.New(&proxy.Config{
		Logger: logger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		RequestHandler: preMw.Wrap(proxy.DefaultHandler{}),
	})
	require.NoError(t, err)

	addrs, err := p.LookupNetIP(ctx, "", host)
	require.NoError(t, err)
	require.Contains(t, addrs, want)
	assert.Zero(t, ups.n.Load(), "Lookup must resolve from hosts, not upstream")
}

// TestLookupNetIP_withRatelimit ensures Lookup is not silently emptied by the
// standalone UDP ratelimit middleware (empty Addr must not share one bucket).
func TestLookupNetIP_withRatelimit(t *testing.T) {
	t.Parallel()

	const host = "lookup-ratelimit.example"
	want := netip.MustParseAddr("203.0.113.10")

	logger := slogutil.NewDiscardLogger()
	ups := &answeringUpstream{a: want}
	rlMw := ratelimit.NewMiddleware(&ratelimit.Config{
		Logger:        logger,
		Ratelimit:     1,
		MaxSize:       ratelimit.DefaultMaxSize,
		SubnetLenIPv4: 24,
		SubnetLenIPv6: 64,
	})

	p, err := proxy.New(&proxy.Config{
		Logger: logger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		RequestHandler: rlMw.Wrap(proxy.DefaultHandler{}),
	})
	require.NoError(t, err)

	ctx := context.Background()
	for i := range 2 {
		addrs, lookupErr := p.LookupNetIP(ctx, "", host)
		require.NoError(t, lookupErr, "lookup %d", i)
		require.Contains(t, addrs, want, "lookup %d", i)
	}

	assert.GreaterOrEqual(t, ups.n.Load(), uint32(2),
		"both Lookups must reach upstream (A queries), not ErrDrop via ratelimit")
}

// countingUpstream counts Exchange calls.
type countingUpstream struct {
	n atomic.Uint32
}

// type check
var _ upstream.Upstream = (*countingUpstream)(nil)

// Exchange implements the [upstream.Upstream] interface for *countingUpstream.
func (u *countingUpstream) Exchange(_ context.Context, m *dns.Msg) (resp *dns.Msg, err error) {
	u.n.Add(1)

	return (&dns.Msg{}).SetReply(m), nil
}

// Address implements the [upstream.Upstream] interface for *countingUpstream.
func (u *countingUpstream) Address() (addr string) { return "counting-test" }

// Close implements the [upstream.Upstream] interface for *countingUpstream.
func (u *countingUpstream) Close() (err error) { return nil }

// answeringUpstream returns a fixed A answer and counts Exchange calls.
type answeringUpstream struct {
	a netip.Addr
	n atomic.Uint32
}

// type check
var _ upstream.Upstream = (*answeringUpstream)(nil)

// Exchange implements the [upstream.Upstream] interface for *answeringUpstream.
func (u *answeringUpstream) Exchange(_ context.Context, m *dns.Msg) (resp *dns.Msg, err error) {
	u.n.Add(1)
	resp = (&dns.Msg{}).SetReply(m)
	if len(m.Question) == 1 && m.Question[0].Qtype == dns.TypeA {
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: u.a.AsSlice(),
		}}
	}

	return resp, nil
}

// Address implements the [upstream.Upstream] interface for *answeringUpstream.
func (u *answeringUpstream) Address() (addr string) { return "answering-test" }

// Close implements the [upstream.Upstream] interface for *answeringUpstream.
func (u *answeringUpstream) Close() (err error) { return nil }
