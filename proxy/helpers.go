package proxy

import (
	"net"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// errECSMismatch is returned when a response's EDNS Client Subnet does not
// match the corresponding query per RFC 7871 Section 7.3.
const errECSMismatch errors.Error = "ecs mismatch in response"

// ecsMismatch reports whether resp must be dropped for caching and pending
// sharing because its ECS SOURCE PREFIX-LENGTH / ADDRESS do not match reqECS.
//
// See RFC 7871 Section 7.3.  Returns false when reqECS is nil, resp is nil, or
// resp carries no ECS option (server does not support ECS).
func ecsMismatch(reqECS *net.IPNet, resp *dns.Msg) (mismatch bool) {
	if reqECS == nil || resp == nil {
		return false
	}

	ecs, _ := ecsFromMsg(resp)
	if ecs == nil {
		return false
	}

	ones, _ := ecs.Mask.Size()
	reqOnes, _ := reqECS.Mask.Size()

	return !ecs.IP.Mask(ecs.Mask).Equal(reqECS.IP.Mask(reqECS.Mask)) || ones != reqOnes
}

// ecsFromMsg returns the subnet from EDNS Client Subnet option of m if any.
func ecsFromMsg(m *dns.Msg) (subnet *net.IPNet, scope int) {
	opt := m.IsEdns0()
	if opt == nil {
		return nil, 0
	}

	var ip net.IP
	var mask net.IPMask
	for _, e := range opt.Option {
		sn, ok := e.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}

		switch sn.Family {
		case 1:
			ip = sn.Address.To4()
			mask = net.CIDRMask(int(sn.SourceNetmask), netutil.IPv4BitLen)
		case 2:
			ip = sn.Address
			mask = net.CIDRMask(int(sn.SourceNetmask), netutil.IPv6BitLen)
		default:
			continue
		}

		return &net.IPNet{IP: ip, Mask: mask}, int(sn.SourceScope)
	}

	return nil, 0
}

// setECS sets the EDNS client subnet option based on ip and scope into m.  It
// returns masked IP and mask length.
func setECS(m *dns.Msg, ip net.IP, scope uint8) (subnet *net.IPNet) {
	const (
		// defaultECSv4 is the default length of network mask for IPv4 address
		// in ECS option.
		defaultECSv4 = 24

		// defaultECSv6 is the default length of network mask for IPv6 address
		// in ECS.  The size of 7 octets is chosen as a reasonable minimum since
		// at least Google's public DNS refuses requests containing the options
		// with longer network masks.
		defaultECSv6 = 56
	)

	e := &dns.EDNS0_SUBNET{
		Code:        dns.EDNS0SUBNET,
		SourceScope: scope,
	}

	subnet = &net.IPNet{}
	if ip4 := ip.To4(); ip4 != nil {
		e.Family = 1
		e.SourceNetmask = defaultECSv4
		subnet.Mask = net.CIDRMask(defaultECSv4, netutil.IPv4BitLen)
		ip = ip4
	} else {
		// Assume the IP address has already been validated.
		e.Family = 2
		e.SourceNetmask = defaultECSv6
		subnet.Mask = net.CIDRMask(defaultECSv6, netutil.IPv6BitLen)
	}
	subnet.IP = ip.Mask(subnet.Mask)
	e.Address = subnet.IP

	// If OPT record already exists so just add EDNS option inside it.  Note
	// that servers may return FORMERR if they meet several OPT RRs.
	if opt := m.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, e)

		return subnet
	}

	// Create an OPT record and add EDNS option inside it.
	o := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
		Option: []dns.EDNS0{e},
	}
	o.SetUDPSize(4096)
	m.Extra = append(m.Extra, o)

	return subnet
}
