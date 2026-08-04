// Package ratelimit provides a rate limiting functionality.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	rate "github.com/beefsack/go-rate"
	"github.com/fcchbjm/dnsproxy/proxy"
	gocache "github.com/patrickmn/go-cache"
)

// middleware implements [proxy.Middleware] with rate limiting functionality.
type middleware struct {
	buckets *gocache.Cache
	logger  *slog.Logger

	// mu protects buckets.
	mu *sync.Mutex

	allowlistAddrs netutil.SliceSubnetSet
	ratelimit      uint
	maxSize        uint
	subnetLenIPv4  uint
	subnetLenIPv6  uint
}

// NewMiddleware returns middleware with rate limiting functionality.  c must be
// valid.
func NewMiddleware(c *Config) (m proxy.Middleware) {
	return &middleware{
		logger:         c.Logger,
		mu:             &sync.Mutex{},
		allowlistAddrs: c.AllowlistAddrs,
		ratelimit:      c.Ratelimit,
		maxSize:        c.MaxSize,
		subnetLenIPv4:  c.SubnetLenIPv4,
		subnetLenIPv6:  c.SubnetLenIPv6,
	}
}

// type check
var _ proxy.Middleware = (*middleware)(nil)

// Wrap implements the [proxy.Middleware] interface for *middleware.  If the
// client is rate limited, it returns [proxy.ErrDrop] to signal that no response
// should be sent.
func (m *middleware) Wrap(h proxy.Handler) (wrapped proxy.Handler) {
	f := func(ctx context.Context, p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
		if dctx.Proto == proxy.ProtoUDP && m.isRatelimited(dctx.Addr.Addr()) {
			m.logger.Debug("ratelimited based on ip only", "addr", dctx.Addr)

			return proxy.ErrDrop
		}

		return h.ServeDNS(ctx, p, dctx)
	}

	return proxy.HandlerFunc(f)
}

// limiterForIP returns a rate limiter for the specified IP address.
func (m *middleware) limiterForIP(ip string) (rl any) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.buckets == nil {
		// cleanupInterval matches default bucket TTL; janitor is best-effort.
		// Insertions still DeleteExpired when at MaxSize so ItemCount cannot
		// grow past MaxSize when expired entries linger.
		m.buckets = gocache.New(bucketTTL, bucketTTL)
	}

	rl, ok := m.buckets.Get(ip)
	if ok {
		return rl
	}

	m.ensureBucketCapacityLocked()

	rl = rate.New(int(m.ratelimit), time.Second)
	m.buckets.Set(ip, rl, bucketTTL)

	return rl
}

// bucketTTL is how long a per-subnet rate-limit bucket is retained.
const bucketTTL = time.Hour

// ensureBucketCapacityLocked makes room for one new bucket.  m.mu must be held.
//
// go-cache ItemCount includes expired entries until they are deleted, while
// Items only returns live ones.  Clear expired first, then evict the oldest
// live bucket until ItemCount is below MaxSize.
func (m *middleware) ensureBucketCapacityLocked() {
	for m.buckets.ItemCount() >= int(m.maxSize) {
		before := m.buckets.ItemCount()
		m.buckets.DeleteExpired()
		if m.buckets.ItemCount() < int(m.maxSize) {
			return
		}
		if !m.evictOldestLocked() {
			return
		}
		if m.buckets.ItemCount() >= before {
			return
		}
	}
}

// evictOldestLocked deletes one live bucket with the earliest expiration.
// m.mu must be held.  Reports whether a key was deleted.
func (m *middleware) evictOldestLocked() (ok bool) {
	items := m.buckets.Items()
	var (
		oldestKey string
		oldestExp int64
		found     bool
	)
	for k, it := range items {
		if !found || it.Expiration < oldestExp {
			oldestKey = k
			oldestExp = it.Expiration
			found = true
		}
	}
	if !found {
		return false
	}

	m.buckets.Delete(oldestKey)

	return true
}

// isRatelimited checks if the specified address should be rate limited.
func (m *middleware) isRatelimited(addr netip.Addr) (ok bool) {
	addr = addr.Unmap()
	if m.allowlistAddrs.Contains(addr) {
		return false
	}

	var pref netip.Prefix
	if addr.Is4() {
		pref = netip.PrefixFrom(addr, int(m.subnetLenIPv4))
	} else {
		pref = netip.PrefixFrom(addr, int(m.subnetLenIPv6))
	}
	pref = pref.Masked()

	// TODO(d.kolyshev):  Improve caching.  Decrease allocations.
	ipStr := pref.Addr().String()
	value := m.limiterForIP(ipStr)
	rl, ok := value.(*rate.RateLimiter)
	if !ok {
		panic(fmt.Sprintf("invalid value found in ratelimit cache: bad type: %T", value))
	}

	allow, _ := rl.Try()

	return !allow
}
