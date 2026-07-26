package proxy

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/fcchbjm/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPendingRequests_ecsMismatchNotShared proves that when an upstream ECS
// option does not match the request (RFC 7871 §7.3), pending followers must not
// receive a cloned copy of that response — the same gate used by cacheResp.
func TestPendingRequests_ecsMismatchNotShared(t *testing.T) {
	t.Parallel()

	pr := newDefaultPendingRequests()
	ctx := context.Background()

	reqECS := &net.IPNet{
		IP:   net.IPv4(1, 2, 3, 0),
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	}

	leaderReq := newHostTestMessage("ecs-mismatch.example")
	setECS(leaderReq, reqECS.IP, 0)

	leader := &DNSContext{
		Req:    leaderReq,
		ReqECS: reqECS,
	}

	loaded, err := pr.queue(ctx, leader)
	require.NoError(t, err)
	require.False(t, loaded)

	followerReq := leaderReq.Copy()
	follower := &DNSContext{
		Req:    followerReq,
		ReqECS: reqECS,
	}

	var (
		followerLoaded bool
		followerErr    error
		wg             sync.WaitGroup
	)
	followerWaiting := make(chan struct{})
	var waitOnce sync.Once
	pr.onFollowerWait = func() {
		waitOnce.Do(func() { close(followerWaiting) })
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		followerLoaded, followerErr = pr.queue(ctx, follower)
	}()
	<-followerWaiting

	// Upstream answers with a conflicting ECS source prefix (different /24).
	badResp := (&dns.Msg{}).SetReply(leaderReq)
	badResp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   leaderReq.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IPv4(8, 8, 8, 8),
	}}
	setECS(badResp, net.IPv4(9, 9, 9, 0), 24)

	require.True(t, ecsMismatch(reqECS, badResp), "fixture must be an ECS mismatch")

	leader.Res = badResp
	pr.done(ctx, leader, nil)

	wg.Wait()

	require.True(t, followerLoaded)
	// Must not share the RFC-invalid response with waiters.
	assert.ErrorIs(t, followerErr, errECSMismatch)
	assert.Nil(t, follower.Res)
}

func TestPendingRequests_ecsMatchStillShared(t *testing.T) {
	t.Parallel()

	pr := newDefaultPendingRequests()
	ctx := context.Background()

	reqECS := &net.IPNet{
		IP:   net.IPv4(1, 2, 3, 0),
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	}

	leaderReq := newHostTestMessage("ecs-match.example")
	setECS(leaderReq, reqECS.IP, 0)

	leader := &DNSContext{Req: leaderReq, ReqECS: reqECS}
	loaded, err := pr.queue(ctx, leader)
	require.NoError(t, err)
	require.False(t, loaded)

	follower := &DNSContext{Req: leaderReq.Copy(), ReqECS: reqECS}
	var (
		followerLoaded bool
		followerErr    error
		wg             sync.WaitGroup
	)
	followerWaiting := make(chan struct{})
	var waitOnce sync.Once
	pr.onFollowerWait = func() {
		waitOnce.Do(func() { close(followerWaiting) })
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		followerLoaded, followerErr = pr.queue(ctx, follower)
	}()
	<-followerWaiting

	okResp := (&dns.Msg{}).SetReply(leaderReq)
	okResp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   leaderReq.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IPv4(8, 8, 8, 8),
	}}
	setECS(okResp, reqECS.IP, 24)

	require.False(t, ecsMismatch(reqECS, okResp))

	leader.Res = okResp
	pr.done(ctx, leader, nil)
	wg.Wait()

	require.True(t, followerLoaded)
	require.NoError(t, followerErr)
	require.NotNil(t, follower.Res)
	require.Len(t, follower.Res.Answer, 1)
}

// TestResolve_ecsMismatchDropsLeaderResponse asserts RFC 7871 §7.3 for the
// leader path: a mismatched ECS answer must not remain as a successful client
// response (same [ecsMismatch] gate as cache / pending followers).
func TestResolve_ecsMismatchDropsLeaderResponse(t *testing.T) {
	t.Parallel()

	u := &testUpstream{
		ans: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: "host.", Ttl: 60},
			A:   net.IPv4(4, 3, 2, 1),
		}},
		// Deliberately disagree with the client subnet derived from Addr.
		ecsIP: net.IPv4(9, 9, 9, 0),
	}

	prx := mustNew(t, &Config{
		Logger:        testLogger,
		UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		},
		TrustedProxies:         defaultTrustedProxies,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheSizeBytes:         64 * 1024,
		PendingRequests:        &PendingRequestsConfig{Enabled: true},
	})
	servicetest.RequireRun(t, prx, testTimeout)

	d := &DNSContext{
		Req:  newHostTestMessage("host"),
		Addr: netip.MustParseAddrPort("1.2.3.0:1234"),
	}

	ctx := testutil.ContextWithTimeout(t, defaultTimeout)
	err := prx.Resolve(ctx, d)

	assert.ErrorIs(t, err, errECSMismatch)
	assert.Nil(t, d.Res)
}
