package proxy

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
)

// pendingRequests handles identical requests that are in progress.  It is used
// to avoid sending the same request multiple times to the upstream server.  The
// implementations are:
//   - [defaultPendingRequests].
//   - [emptyPendingRequests].
type pendingRequests interface {
	// queue is called for each request.  It returns false if there are no
	// identical requests in progress.  Otherwise it blocks until the first
	// request is completed, or until ctx is canceled.  On cancel it returns
	// loaded=true and ctx.Err(); the caller must not call done.  On a completed
	// peer it returns loaded=true and the error that occurred during that
	// peer's resolution (which may be nil).
	queue(ctx context.Context, dctx *DNSContext) (loaded bool, err error)

	// done must be called after the request is completed, if queue returned
	// false for it.
	done(ctx context.Context, dctx *DNSContext, err error)
}

// defaultPendingRequests is a default implementation of the [pendingRequests]
// interface.  It must be created with [newDefaultPendingRequests].
type defaultPendingRequests struct {
	storage *syncutil.Map[string, *pendingRequest]

	// onFollowerWait, if non-nil, is called after a duplicate request has been
	// registered and before the waiter blocks on finish.  Tests use it as a
	// deterministic barrier; production leaves it nil.
	onFollowerWait func()
}

// pendingRequest is a structure that stores the query state and result.
type pendingRequest struct {
	// finish is a channel that is closed when the request is completed.  It is
	// used to block request processing for any but the first one.
	finish chan struct{}

	// resolveErr is the error that occurred during the request processing.  It
	// may be nil.  It must only be accessed for reading after the finish
	// channel is closed.
	resolveErr error

	// cloneDNSCtx is a clone of the DNSContext that was used to create the
	// pendingRequest and store its result.  It must only be accessed for
	// reading after the finish channel is closed.
	cloneDNSCtx *DNSContext
}

// newDefaultPendingRequests creates a new instance of DefaultPendingRequests.
func newDefaultPendingRequests() (pr *defaultPendingRequests) {
	return &defaultPendingRequests{
		storage: syncutil.NewMap[string, *pendingRequest](),
	}
}

// type check
var _ pendingRequests = (*defaultPendingRequests)(nil)

// queue implements the [pendingRequests] interface for
// [defaultPendingRequests].
func (pr *defaultPendingRequests) queue(
	ctx context.Context,
	dctx *DNSContext,
) (loaded bool, err error) {
	var key []byte
	if dctx.ReqECS != nil {
		ones, _ := dctx.ReqECS.Mask.Size()
		key = msgToKeyWithSubnet(dctx.Req, dctx.ReqECS.IP, ones)
	} else {
		key = msgToKey(dctx.Req)
	}

	req := &pendingRequest{
		finish: make(chan struct{}),
	}

	pending, loaded := pr.storage.LoadOrStore(string(key), req)
	if !loaded {
		return false, nil
	}

	if f := pr.onFollowerWait; f != nil {
		f()
	}

	select {
	case <-pending.finish:
		// Peer finished; clone / ECS gate below.
	case <-ctx.Done():
		// ctx and finish may both be ready in the same window. Prefer the peer
		// result so followers do not discard a completed response as cancel.
		select {
		case <-pending.finish:
			// Fall through to clone / ECS path.
		default:
			// Follower canceled: do not Delete/close the pending entry.
			return true, ctx.Err()
		}
	}

	origDNSCtx := pending.cloneDNSCtx

	// TODO(a.garipov):  Perhaps, statistics should be calculated separately for
	// each request.
	dctx.queryStatistics = origDNSCtx.queryStatistics
	dctx.Upstream = origDNSCtx.Upstream
	if origDNSCtx.Res != nil {
		// Same RFC 7871 §7.3 gate as [Proxy.cacheResp]: do not share a response
		// whose ECS does not match the request.
		if ecsMismatch(dctx.ReqECS, origDNSCtx.Res) {
			return loaded, errECSMismatch
		}

		// TODO(e.burkov):  Add cloner for DNS messages.
		dctx.Res = origDNSCtx.Res.Copy().SetReply(dctx.Req)
	}

	return loaded, pending.resolveErr
}

// done implements the [pendingRequests] interface for [defaultPendingRequests].
func (pr *defaultPendingRequests) done(ctx context.Context, dctx *DNSContext, err error) {
	var key []byte
	if dctx.ReqECS != nil {
		ones, _ := dctx.ReqECS.Mask.Size()
		key = msgToKeyWithSubnet(dctx.Req, dctx.ReqECS.IP, ones)
	} else {
		key = msgToKey(dctx.Req)
	}

	pending, ok := pr.storage.Load(string(key))
	if !ok {
		panic(fmt.Errorf("loading pending request: key %x: %w", key, errors.ErrNoValue))
	}

	pending.resolveErr = err

	cloneCtx := &DNSContext{
		Upstream:        dctx.Upstream,
		queryStatistics: dctx.queryStatistics,
	}

	if dctx.Res != nil {
		cloneCtx.Res = dctx.Res.Copy()
	}

	pending.cloneDNSCtx = cloneCtx

	pr.storage.Delete(string(key))
	close(pending.finish)
}

// emptyPendingRequests is a no-op implementation of PendingRequests.  It is
// used when pending requests are not needed.
type emptyPendingRequests struct{}

// type check
var _ pendingRequests = emptyPendingRequests{}

// queue implements the [pendingRequests] interface for [emptyPendingRequests].
// It always returns false and does not block.
func (emptyPendingRequests) queue(_ context.Context, _ *DNSContext) (loaded bool, err error) {
	return false, nil
}

// done implements the [pendingRequests] interface for [emptyPendingRequests].
func (emptyPendingRequests) done(_ context.Context, _ *DNSContext, _ error) {}
