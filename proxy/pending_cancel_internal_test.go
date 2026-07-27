package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPendingRequests_followerCancelWhileWaiting proves ADV-012: a follower
// blocked on an in-flight peer must unblock on ctx cancel with loaded=true and
// must not call done (leader still owns the pending entry).
func TestPendingRequests_followerCancelWhileWaiting(t *testing.T) {
	t.Parallel()

	pr := newDefaultPendingRequests()

	leaderReq := newHostTestMessage("cancel-wait.example")
	leader := &DNSContext{Req: leaderReq}

	loaded, err := pr.queue(context.Background(), leader)
	require.NoError(t, err)
	require.False(t, loaded)

	followerWaiting := make(chan struct{})
	var waitOnce sync.Once
	pr.onFollowerWait = func() {
		waitOnce.Do(func() { close(followerWaiting) })
	}

	followerCtx, cancelFollower := context.WithCancel(context.Background())
	defer cancelFollower()

	follower := &DNSContext{Req: leaderReq.Copy()}

	var (
		followerLoaded bool
		followerErr    error
		wg             sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		followerLoaded, followerErr = pr.queue(followerCtx, follower)
	}()

	select {
	case <-followerWaiting:
	case <-time.After(testTimeout):
		t.Fatal("follower did not reach wait")
	}

	cancelFollower()
	wg.Wait()

	require.True(t, followerLoaded)
	assert.ErrorIs(t, followerErr, context.Canceled)
	assert.Nil(t, follower.Res)

	// Leader still owns the entry: done must succeed without panic / double-close.
	leader.Res = (&dns.Msg{}).SetReply(leaderReq)
	leader.Res.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   leaderReq.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IPv4(8, 8, 8, 8),
	}}
	require.NotPanics(t, func() {
		pr.done(context.Background(), leader, nil)
	})

	// Entry is gone; a new request becomes the next leader.
	next := &DNSContext{Req: leaderReq.Copy()}
	loaded, err = pr.queue(context.Background(), next)
	require.NoError(t, err)
	require.False(t, loaded)
	require.NotPanics(t, func() {
		pr.done(context.Background(), next, nil)
	})
}

// TestPendingRequests_followerDeadlineWhileWaiting proves a follower blocked on
// an in-flight peer unblocks on deadline with loaded=true and DeadlineExceeded;
// the leader still owns the pending entry.
func TestPendingRequests_followerDeadlineWhileWaiting(t *testing.T) {
	t.Parallel()

	pr := newDefaultPendingRequests()

	leaderReq := newHostTestMessage("deadline-wait.example")
	leader := &DNSContext{Req: leaderReq}

	loaded, err := pr.queue(context.Background(), leader)
	require.NoError(t, err)
	require.False(t, loaded)

	followerWaiting := make(chan struct{})
	var waitOnce sync.Once
	pr.onFollowerWait = func() {
		waitOnce.Do(func() { close(followerWaiting) })
	}

	followerCtx, cancelFollower := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelFollower()

	follower := &DNSContext{Req: leaderReq.Copy()}

	var (
		followerLoaded bool
		followerErr    error
		wg             sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		followerLoaded, followerErr = pr.queue(followerCtx, follower)
	}()

	select {
	case <-followerWaiting:
	case <-time.After(testTimeout):
		t.Fatal("follower did not reach wait")
	}

	wg.Wait()

	require.True(t, followerLoaded)
	assert.ErrorIs(t, followerErr, context.DeadlineExceeded)
	assert.Nil(t, follower.Res)

	// Leader still owns the entry: done must succeed without panic / double-close.
	leader.Res = (&dns.Msg{}).SetReply(leaderReq)
	leader.Res.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   leaderReq.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IPv4(1, 1, 1, 1),
	}}
	require.NotPanics(t, func() {
		pr.done(context.Background(), leader, nil)
	})
}
