package proxy

import (
	"context"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/fcchbjm/dnsproxy/proxyutil"
	"github.com/fcchbjm/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// lookupResult represents the result of an IP address lookup.
type lookupResult struct {
	resp *dns.Msg
	err  error
}

// lookupIPAddr resolves the specified host IP addresses.  It is intended to be
// used as a goroutine.  It uses the same validation and request-handler path as
// inbound queries, but does not write a DNS response to the network.
func (p *Proxy) lookupIPAddr(
	ctx context.Context,
	host string,
	qtype uint16,
	ch chan *lookupResult,
) {
	defer slogutil.RecoverAndLog(ctx, p.logger)

	req := (&dns.Msg{}).SetQuestion(host, qtype)

	// Not an inbound UDP client: Addr is unset, so ProtoUDP would share the
	// ratelimit "invalid IP" bucket and silently ErrDrop.  ProtoTCP keeps
	// RequestHandler/hosts but skips UDP-only ratelimit.
	//
	// TODO(d.kolyshev): Investigate why the client address is not defined.
	d := p.newDNSContext(ProtoTCP, req, netip.AddrPort{})
	err := p.serveDNSRequest(ctx, d)
	if errors.Is(err, ErrDrop) {
		ch <- &lookupResult{}

		return
	}

	ch <- &lookupResult{
		resp: d.Res,
		err:  err,
	}
}

// ErrEmptyHost is returned by LookupIPAddr when the host is empty and can't be
// resolved.
const ErrEmptyHost = errors.Error("host is empty")

// type check
var _ upstream.Resolver = (*Proxy)(nil)

// LookupNetIP implements the [upstream.Resolver] interface for *Proxy.  It
// resolves the specified host IP addresses by sending two DNS queries (A and
// AAAA) in parallel.  It returns both results for those two queries.
func (p *Proxy) LookupNetIP(
	ctx context.Context,
	_ string,
	host string,
) (addrs []netip.Addr, err error) {
	if host == "" {
		return nil, ErrEmptyHost
	}

	host = dns.Fqdn(host)

	ch := make(chan *lookupResult)
	go p.lookupIPAddr(ctx, host, dns.TypeA, ch)
	go p.lookupIPAddr(ctx, host, dns.TypeAAAA, ch)

	var errs []error
	for range 2 {
		result := <-ch
		if result.err != nil {
			errs = append(errs, result.err)

			continue
		}

		if result.resp == nil {
			continue
		}

		addrs = appendAnswerAddrs(addrs, result.resp.Answer)
	}

	if len(addrs) == 0 && len(errs) != 0 {
		return addrs, errors.Join(errs...)
	}

	if p.preferIPv6 {
		slices.SortStableFunc(addrs, netutil.PreferIPv6)
	} else {
		slices.SortStableFunc(addrs, netutil.PreferIPv4)
	}

	return addrs, nil
}

// appendAnswerAddrs returns addrs with addresses appended from the given ans.
func appendAnswerAddrs(addrs []netip.Addr, ans []dns.RR) (res []netip.Addr) {
	for _, ansRR := range ans {
		a := proxyutil.IPFromRR(ansRR)
		if a != (netip.Addr{}) {
			addrs = append(addrs, a)
		}
	}

	return addrs
}
