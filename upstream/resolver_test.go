package upstream_test

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/fcchbjm/dnsproxy/dnsproxytest"
	"github.com/fcchbjm/dnsproxy/internal/bootstrap"
	"github.com/fcchbjm/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envOrDefault returns the value of the environment variable k, or def if it is
// empty or unset.
func envOrDefault(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}

	return def
}

// skipIfRestrictedPublicDNSCrypt skips tests that need the public AdGuard
// DNSCrypt endpoint when DNSPROXY_TEST_UPSTREAMS is set and
// DNSPROXY_TEST_INCLUDE_ENCRYPTED is not enabled.
func skipIfRestrictedPublicDNSCrypt(t *testing.T) {
	t.Helper()

	if os.Getenv("DNSPROXY_TEST_UPSTREAMS") == "" {
		return
	}

	v := strings.TrimSpace(os.Getenv("DNSPROXY_TEST_INCLUDE_ENCRYPTED"))
	if strings.EqualFold(v, "1") || strings.EqualFold(v, "true") {
		return
	}

	t.Skip("restricted network profile; set DNSPROXY_TEST_INCLUDE_ENCRYPTED=1 to enable public DNSCrypt tests")
}

func TestNewUpstreamResolver(t *testing.T) {
	ups := &dnsproxytest.Upstream{
		OnAddress: func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: netip.MustParseAddr("1.2.3.4").AsSlice(),
			}}

			return resp, nil
		},
	}

	r := upstream.ResolverFromUpstream(ups, testLogger, nil)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	ipAddrs, err := r.LookupNetIP(ctx, bootstrap.NetworkIP, "cloudflare-dns.com")
	require.NoError(t, err)

	assert.NotEmpty(t, ipAddrs)
}

func TestNewUpstreamResolver_validity(t *testing.T) {
	t.Parallel()

	withTimeoutOpt := &upstream.Options{
		Logger:  testLogger,
		Timeout: 3 * time.Second,
	}

	// Overridable so that restricted networks can still run these cases.
	testIP := envOrDefault("DNSPROXY_TEST_RESOLVER_IP", "1.1.1.1")
	testLookupHost := envOrDefault("DNSPROXY_TEST_LOOKUP_HOST", "cloudflare-dns.com")

	testCases := []upstreamResolverValidityCase{{
		name:       "udp",
		addr:       testIP + ":53",
		wantErrMsg: "",
	}, {
		name:       "dot",
		addr:       "tls://" + testIP,
		wantErrMsg: "",
	}, {
		name:       "doh",
		addr:       "https://" + testIP + "/dns-query",
		wantErrMsg: "",
	}, {
		name:       "sdns",
		addr:       "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		wantErrMsg: "",
	}, {
		name: "tcp",
		// Use the same resolver address for TCP tests so that restricted
		// environments can override it with DNSPROXY_TEST_RESOLVER_IP.
		addr:       "tcp://" + testIP,
		wantErrMsg: "",
	}, {
		name: "invalid_tls",
		addr: "tls://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_https",
		addr: "https://dns.adguard.com/dns-query",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_tcp",
		addr: "tcp://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_no_scheme",
		addr: "dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runUpstreamResolverValidityCase(t, tc, withTimeoutOpt, testLookupHost)
		})
	}
}

// upstreamResolverValidityCase is a single NewUpstreamResolver validity test
// case.
type upstreamResolverValidityCase struct {
	// name is the subtest name.
	name string

	// addr is the upstream address to pass to NewUpstreamResolver.
	addr string

	// wantErrMsg is the expected error message.  Empty means success.
	wantErrMsg string
}

// runUpstreamResolverValidityCase exercises a single NewUpstreamResolver
// validity case.  opts and testLookupHost must not be nil.
func runUpstreamResolverValidityCase(
	t *testing.T,
	tc upstreamResolverValidityCase,
	opts *upstream.Options,
	testLookupHost string,
) {
	t.Helper()

	// The public DNSCrypt stamp is unreachable on restricted networks.
	if tc.name == "sdns" {
		skipIfRestrictedPublicDNSCrypt(t)
	}

	r, err := upstream.NewUpstreamResolver(tc.addr, opts)
	if tc.wantErrMsg != "" {
		assert.Equal(t, tc.wantErrMsg, err.Error())
		if nberr := (&upstream.NotBootstrapError{}); errors.As(err, &nberr) {
			assert.NotNil(t, r)
		}

		return
	}

	require.NoError(t, err)

	addrs, err := r.LookupNetIP(context.Background(), "ip", testLookupHost)
	require.NoError(t, err)

	assert.NotEmpty(t, addrs)
}
