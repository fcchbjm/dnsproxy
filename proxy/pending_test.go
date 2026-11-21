package proxy_test

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/fcchbjm/dnsproxy/dnsproxytest"
	proxytest "github.com/fcchbjm/dnsproxy/internal/dnsproxytest"
	"github.com/fcchbjm/dnsproxy/proxy"
	"github.com/fcchbjm/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertEqualResponses is a helper function that checks if two DNS messages are
// equal, excluding their ID.
//
// TODO(e.burkov):  Cosider using go-cmp.
func assertEqualResponses(tb testing.TB, expected, actual *dns.Msg) {
	tb.Helper()

	if expected == nil {
		require.Nil(tb, actual)

		return
	}

	require.NotNil(tb, actual)

	expectedHdr, actualHdr := expected.MsgHdr, actual.MsgHdr
	expectedHdr.Id, actualHdr.Id = 0, 0
	assert.Equal(tb, expectedHdr, actualHdr)

	assert.Equal(tb, expected.Question, actual.Question)
	assert.Equal(tb, expected.Answer, actual.Answer)
	assert.Equal(tb, expected.Ns, actual.Ns)
	assert.Equal(tb, expected.Extra, actual.Extra)
}

func TestPendingRequests(t *testing.T) {
	t.Parallel()

	const reqsNum = 100

	// arriveWG holds every handler at the same gate so they enter Resolve
	// together.  The first upstream Exchange then waits until all handlers have
	// started Resolve (and yields so waiters can join the pending queue) before
	// answering — proving coalesce rather than racing Done-before-queue.
	arriveWG := &sync.WaitGroup{}
	arriveWG.Add(reqsNum)

	var (
		resolveStarted atomic.Int64
		exchangeCount  atomic.Int64
	)

	reqHandler := &dnsproxytest.Handler{
		OnHandle: func(ctx context.Context, p *proxy.Proxy, d *proxy.DNSContext) (err error) {
			arriveWG.Done()
			arriveWG.Wait()
			resolveStarted.Add(1)

			return p.Resolve(ctx, d)
		},
	}

	// Shared cacheable A RR: late leaders (if any) hit cache instead of a second
	// upstream path.  Do not use PanicT.
	var (
		replyOnce sync.Once
		reply     *dns.Msg
	)
	u := &dnsproxytest.Upstream{
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			exchangeCount.Add(1)

			deadline := time.Now().Add(testTimeout)
			for resolveStarted.Load() < reqsNum && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			// Let waiters progress from Resolve entry into pending.queue.
			for range 256 {
				runtime.Gosched()
			}

			replyOnce.Do(func() {
				reply = (&dns.Msg{}).SetReply(req)
				reply.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   req.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.IPv4(1, 2, 3, 4),
				}}
			})

			resp = reply.Copy()
			resp.Id = req.Id

			return resp, nil
		},
		OnAddress: func() (addr string) { return "" },
		OnClose:   func() (err error) { return nil },
	}

	p, err := proxy.New(&proxy.Config{
		Logger:         testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies: proxytest.DefaultTrustedProxies,
		PendingRequests: &proxy.PendingRequestsConfig{
			Enabled: true,
		},
		RequestHandler:         reqHandler,
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort)},
		CacheSizeBytes:         proxytest.CacheSize,
		CacheEnabled:           true,
		DNSSECEnabled:          true,
		EnableEDNSClientSubnet: true,
	})
	require.NoError(t, err)

	servicetest.RequireRun(t, p, proxytest.Timeout)

	addr := p.Addr(proxy.ProtoTCP).String()
	client := &dns.Client{
		Net:     string(proxy.ProtoTCP),
		Timeout: proxytest.Timeout,
	}

	resolveWG := &sync.WaitGroup{}
	responses := make([]*dns.Msg, reqsNum)
	errs := make([]error, reqsNum)

	for i := range reqsNum {
		req := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA)
		resolveWG.Go(func() {
			reqCtx := testutil.ContextWithTimeout(t, proxytest.Timeout)
			responses[i], _, errs[i] = client.ExchangeContext(reqCtx, req, addr)
		})
	}

	resolveWG.Wait()

	require.NoError(t, errs[0])
	// Within the coalesce window only one upstream exchange should occur.
	require.Equal(t, int64(1), exchangeCount.Load())

	for i, resp := range responses[:len(responses)-1] {
		assert.Equal(t, errs[i], errs[i+1])
		assertEqualResponses(t, resp, responses[i+1])
	}
}
