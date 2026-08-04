package ratelimit

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	rate "github.com/beefsack/go-rate"
	gocache "github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_maxSizeEvicts(t *testing.T) {
	t.Parallel()

	const maxSize = 2

	mw := NewMiddleware(&Config{
		Logger:        slogutil.NewDiscardLogger(),
		Ratelimit:     1000,
		MaxSize:       maxSize,
		SubnetLenIPv4: 32,
		SubnetLenIPv6: 128,
	})
	inner, ok := mw.(*middleware)
	require.True(t, ok)

	addrs := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("192.0.2.4"),
		netip.MustParseAddr("192.0.2.5"),
	}
	for _, a := range addrs {
		assert.False(t, inner.isRatelimited(a), "high ratelimit must allow first hit: %s", a)
		require.NotNil(t, inner.buckets)
		assert.LessOrEqual(t, inner.buckets.ItemCount(), maxSize)
	}

	assert.Equal(t, maxSize, inner.buckets.ItemCount())
}

// TestMiddleware_maxSizeClearsExpired covers go-cache ItemCount including
// expired entries while Items omits them: without DeleteExpired, MaxSize would
// fail to evict and the map could grow past the cap.
func TestMiddleware_maxSizeClearsExpired(t *testing.T) {
	t.Parallel()

	const maxSize = 2

	mw := NewMiddleware(&Config{
		Logger:        slogutil.NewDiscardLogger(),
		Ratelimit:     1000,
		MaxSize:       maxSize,
		SubnetLenIPv4: 32,
		SubnetLenIPv6: 128,
	})
	inner, ok := mw.(*middleware)
	require.True(t, ok)

	// No janitor: expired entries stay until DeleteExpired.
	inner.buckets = gocache.New(time.Hour, 0)
	shortTTL := 15 * time.Millisecond
	for i := range maxSize {
		key := fmt.Sprintf("192.0.2.%d", i+1)
		inner.buckets.Set(key, rate.New(1000, time.Second), shortTTL)
	}
	require.Equal(t, maxSize, inner.buckets.ItemCount())

	require.Eventually(t, func() bool {
		return len(inner.buckets.Items()) == 0
	}, time.Second, 5*time.Millisecond)
	// Expired but not yet removed: ItemCount still reports maxSize.
	require.Equal(t, maxSize, inner.buckets.ItemCount())
	require.Empty(t, inner.buckets.Items())

	assert.False(t, inner.isRatelimited(netip.MustParseAddr("198.51.100.1")))
	assert.LessOrEqual(t, inner.buckets.ItemCount(), maxSize)

	assert.False(t, inner.isRatelimited(netip.MustParseAddr("198.51.100.2")))
	assert.LessOrEqual(t, inner.buckets.ItemCount(), maxSize)

	assert.False(t, inner.isRatelimited(netip.MustParseAddr("198.51.100.3")))
	assert.LessOrEqual(t, inner.buckets.ItemCount(), maxSize)
	assert.Equal(t, maxSize, inner.buckets.ItemCount())
}

func TestConfig_Validate_maxSize(t *testing.T) {
	t.Parallel()

	err := (&Config{
		Logger:        slogutil.NewDiscardLogger(),
		Ratelimit:     1,
		MaxSize:       0,
		SubnetLenIPv4: 24,
		SubnetLenIPv6: 64,
	}).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MaxSize")
}

func TestConfig_Validate_subnetLenIPv6Name(t *testing.T) {
	t.Parallel()

	err := (&Config{
		Logger:        slogutil.NewDiscardLogger(),
		Ratelimit:     1,
		MaxSize:       DefaultMaxSize,
		SubnetLenIPv4: 24,
		SubnetLenIPv6: 129,
	}).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SubnetLenIPv6")
}
