package ratelimit

import (
	"log/slog"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/validate"
)

// DefaultMaxSize is the Standalone default for [Config.MaxSize] when UDP
// ratelimit is enabled.  It bounds per-subnet bucket growth under multi-source
// scans while leaving headroom for typical client diversity with /24 and /64
// aggregation (on the order of ~10k small go-rate entries, not unbounded map
// growth).
const DefaultMaxSize = 10_000

// Config is the configuration for the ratelimit middleware.
type Config struct {
	// Logger is used for logging in the ratelimit middleware. It must not be
	// nil.
	Logger *slog.Logger

	// AllowlistAddrs is a slice of IP addresses excluded from rate limiting.
	AllowlistAddrs netutil.SliceSubnetSet

	// Ratelimit is a maximum number of requests per second from a given IP.  It
	// must be positive.
	Ratelimit uint

	// MaxSize is the maximum number of per-subnet rate-limit buckets retained.
	// When full, expired buckets are purged and the oldest live bucket is
	// evicted before a new one is inserted.  Must be positive (breaking for
	// embedders that previously omitted it; use [DefaultMaxSize]).
	MaxSize uint

	// SubnetLenIPv4 is a subnet length for IPv4 addresses used for rate
	// limiting requests.
	SubnetLenIPv4 uint

	// SubnetLenIPv6 is a subnet length for IPv6 addresses used for rate
	// limiting requests.
	SubnetLenIPv6 uint
}

// type check
var _ validate.Interface = (*Config)(nil)

// Validate implements the [validate.Interface] interface for *Config.
func (c *Config) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return errors.Join(
		validate.Positive("Ratelimit", c.Ratelimit),
		validate.Positive("MaxSize", c.MaxSize),
		validate.NotNil("Logger", c.Logger),
		validate.NoGreaterThan("SubnetLenIPv4", c.SubnetLenIPv4, netutil.IPv4BitLen),
		validate.NoGreaterThan("SubnetLenIPv6", c.SubnetLenIPv6, netutil.IPv6BitLen),
	)
}
