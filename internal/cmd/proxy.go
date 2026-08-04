package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/fcchbjm/dnsproxy/internal/dnsmsg"
	"github.com/fcchbjm/dnsproxy/internal/middleware"
	proxynetutil "github.com/fcchbjm/dnsproxy/internal/netutil"
	"github.com/fcchbjm/dnsproxy/proxy"
	"github.com/fcchbjm/dnsproxy/ratelimit"
	"github.com/fcchbjm/dnsproxy/upstream"
	"gopkg.in/yaml.v3"
)

// defaultHTTPTimeout is the default timeout for HTTP server operations.
//
// TODO(a.garipov):  Consider making configurable.
const defaultHTTPTimeout = 10 * time.Second

// defaultTLSTimeout is the standalone dnsproxy default for DoT handshake and
// idle read.  Library embedders that leave [proxy.Config.TLSTimeout] zero still
// get [proxy.DefaultTLSTimeout] (600s).
const defaultTLSTimeout = 60 * time.Second

// TODO(e.burkov):  Use a separate type for the YAML configuration file.

// createProxyConfig initializes [proxy.Config].  l must not be nil.
func createProxyConfig(
	ctx context.Context,
	l *slog.Logger,
	conf *configuration,
) (proxyConf *proxy.Config, err error) {
	hostsFiles, err := conf.hostsFiles(ctx, l)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	hosts, err := middleware.ReadHosts(ctx, l, hostsFiles)
	if err != nil {
		return nil, fmt.Errorf("reading hosts files: %w", err)
	}

	preMw := middleware.New(&middleware.Config{
		Logger: l.With(slogutil.KeyPrefix, "pre_handler_mw"),
		// TODO(e.burkov):  Use the configured message constructor.
		MessageConstructor: dnsmsg.DefaultMessageConstructor{},
		HaltIPv6:           conf.IPv6Disabled,
		HostsFiles:         hosts,
	})

	ratelimitMw, err := conf.newRatelimitMw(l)
	if err != nil {
		return nil, fmt.Errorf("ratelimit mw: %w", err)
	}

	httpConf := &proxy.HTTPConfig{
		ServerHeader:          conf.HTTPSServerName,
		Routes:                conf.DoHRoutes,
		ReadTimeout:           defaultHTTPTimeout,
		WriteTimeout:          defaultHTTPTimeout,
		HTTP3Enabled:          conf.HTTP3,
		InsecureEnabled:       conf.DoHInsecureEnabled,
		MaxConcurrentRequests: conf.DoHMaxConcurrent,
	}

	if uiStr := conf.HTTPSUserinfo; uiStr != "" {
		user, pass, ok := strings.Cut(uiStr, ":")
		if ok {
			httpConf.Userinfo = url.UserPassword(user, pass)
		} else {
			httpConf.Userinfo = url.User(user)
		}
	}

	proxyConf = &proxy.Config{
		Logger:                   l.With(slogutil.KeyPrefix, proxy.LogPrefix),
		CacheEnabled:             conf.Cache,
		CacheSizeBytes:           conf.CacheSizeBytes,
		CacheMinTTL:              conf.CacheMinTTL,
		CacheMaxTTL:              conf.CacheMaxTTL,
		CacheOptimisticAnswerTTL: time.Duration(conf.OptimisticAnswerTTL),
		CacheOptimisticMaxAge:    time.Duration(conf.OptimisticMaxAge),
		CacheOptimistic:          conf.CacheOptimistic,
		RefuseAny:                conf.RefuseAny,
		// Default: empty set - do not trust any direct peer for DoH client-IP
		// headers or Proxy Protocol v2.  Operators behind an LB must set
		// --trusted-proxies / trusted-proxies to the LB CIDRs explicitly.
		TrustedProxies:             netutil.SliceSubnetSet{},
		EnableEDNSClientSubnet:     conf.EnableEDNSSubnet,
		UDPBufferSize:              conf.UDPBufferSize,
		MaxGoroutines:              conf.MaxGoRoutines,
		MaxTCPConnections:          conf.MaxTCPConnections,
		UsePrivateRDNS:             conf.UsePrivateRDNS,
		DNSSECEnabled:              conf.DNSSECEnabled,
		TCPProxyProtocolV2Enabled:  conf.TCPProxyProtocolV2Enabled,
		TLSProxyProtocolV2Enabled:  conf.TLSProxyProtocolV2Enabled,
		ProxyProtocolV2ReadTimeout: time.Duration(conf.ProxyProtocolV2ReadTimeout),
		TLSTimeout:                 time.Duration(conf.TLSTimeout),
		PrivateSubnets:             netutil.SubnetSetFunc(netutil.IsLocallyServed),
		RequestHandler:             ratelimitMw.Wrap(preMw.Wrap(proxy.DefaultHandler{})),
		PendingRequests: &proxy.PendingRequestsConfig{
			Enabled: conf.PendingRequestsEnabled,
		},
		HTTPConfig: httpConf,
	}

	if conf.CacheOptimistic && conf.HostsFileEnabled {
		// Optimistic refresh calls replyFromUpstream directly and skips the
		// hosts middleware wrapped into RequestHandler.
		l.Warn(
			"cache-optimistic with hosts-file-enabled: optimistic refresh bypasses hosts middleware; " +
				"do not rely on hosts overrides for expired-cache refreshes",
		)
	}

	conf.initBogusNXDomain(ctx, l, proxyConf)

	var errs []error
	errs = append(errs, conf.initUpstreams(ctx, l, proxyConf))
	errs = append(errs, conf.initEDNS(ctx, l, proxyConf))
	errs = append(errs, conf.initTLSConfig(proxyConf))
	errs = append(errs, conf.initDNSCryptConfig(proxyConf))
	errs = append(errs, conf.initListenAddrs(proxyConf))
	errs = append(errs, conf.initSubnets(proxyConf))
	errs = append(errs, conf.initTrustedProxies(l, proxyConf))

	return proxyConf, errors.Join(errs...)
}

// isEmpty returns false if uc contains at least a single upstream.  uc must not
// be nil.
//
// TODO(e.burkov):  Think of a better way to validate the config.  Perhaps,
// return an error from [ParseUpstreamsConfig] if no upstreams were initialized.
func isEmpty(uc *proxy.UpstreamConfig) (ok bool) {
	return len(uc.Upstreams) == 0 &&
		len(uc.DomainReservedUpstreams) == 0 &&
		len(uc.SpecifiedDomainUpstreams) == 0
}

// newRatelimitMw returns the ratelimit middleware.  In case of invalid
// ratelimit configuration returns an error. l must not be nil.
func (conf *configuration) newRatelimitMw(l *slog.Logger) (mw proxy.Middleware, err error) {
	if conf.Ratelimit == 0 {
		return proxy.MiddlewareFunc(proxy.PassThrough), nil
	}

	rlConf := &ratelimit.Config{
		Logger:        l.With(slogutil.KeyPrefix, "ratelimit"),
		Ratelimit:     conf.Ratelimit,
		MaxSize:       conf.RatelimitMaxSize,
		SubnetLenIPv4: conf.RatelimitSubnetLenIPv4,
		SubnetLenIPv6: conf.RatelimitSubnetLenIPv6,
	}
	if err = rlConf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return ratelimit.NewMiddleware(rlConf), nil
}

// defaultLocalTimeout is the default timeout for local operations.
const defaultLocalTimeout = 1 * time.Second

// initUpstreams inits upstream-related config fields.
//
// TODO(d.kolyshev): Join errors.
func (conf *configuration) initUpstreams(
	ctx context.Context,
	l *slog.Logger,
	config *proxy.Config,
) (err error) {
	httpVersions := upstream.DefaultHTTPVersions
	if conf.HTTP3 {
		httpVersions = []upstream.HTTPVersion{
			upstream.HTTPVersion3,
			upstream.HTTPVersion2,
			upstream.HTTPVersion11,
		}
	}

	timeout := time.Duration(conf.Timeout)
	bootOpts := &upstream.Options{
		Logger:             l,
		HTTPVersions:       httpVersions,
		InsecureSkipVerify: conf.Insecure,
		Timeout:            timeout,
	}
	boot, err := initBootstrap(ctx, l, conf.BootstrapDNS, bootOpts)
	if err != nil {
		return fmt.Errorf("initializing bootstrap: %w", err)
	}

	upsOpts := &upstream.Options{
		Logger:             l,
		HTTPVersions:       httpVersions,
		InsecureSkipVerify: conf.Insecure,
		Bootstrap:          boot,
		Timeout:            timeout,
	}
	upstreams, err := loadNamedServersList(conf.Upstreams, "upstreams list")
	if err != nil {
		return err
	}

	config.UpstreamConfig, err = proxy.ParseUpstreamsConfig(upstreams, upsOpts)
	if err != nil {
		return fmt.Errorf("parsing upstreams configuration: %w", err)
	}

	privateUpsOpts := privateRDNSUpstreamOptions(l, httpVersions, boot, conf.Insecure, timeout)
	config.PrivateRDNSUpstreamConfig, err = loadOptionalUpstreamConfig(
		conf.PrivateRDNSUpstreams,
		privateUpsOpts,
		"private rdns upstreams list",
		"private rdns upstreams configuration",
	)
	if err != nil {
		return err
	}

	config.Fallbacks, err = loadOptionalUpstreamConfig(
		conf.Fallbacks,
		upsOpts,
		"fallback upstreams list",
		"fallback upstreams configuration",
	)
	if err != nil {
		return err
	}

	return applyUpstreamMode(config, conf.UpstreamMode)
}

// loadOptionalUpstreamConfig loads and parses an upstream list.  Empty configs
// are returned as nil so callers can assign the result directly.
func loadOptionalUpstreamConfig(
	sources []string,
	opts *upstream.Options,
	loadWhat, parseWhat string,
) (uc *proxy.UpstreamConfig, err error) {
	servers, err := loadNamedServersList(sources, loadWhat)
	if err != nil {
		return nil, err
	}

	uc, err = proxy.ParseUpstreamsConfig(servers, opts)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", parseWhat, err)
	}

	if isEmpty(uc) {
		return nil, nil
	}

	return uc, nil
}

// applyUpstreamMode sets config.UpstreamMode from the configured string, or
// load-balance when empty.
func applyUpstreamMode(config *proxy.Config, mode string) (err error) {
	if mode == "" {
		config.UpstreamMode = proxy.UpstreamModeLoadBalance

		return nil
	}

	err = config.UpstreamMode.UnmarshalText([]byte(mode))
	if err != nil {
		return fmt.Errorf("parsing upstream mode: %w", err)
	}

	return nil
}

// privateRDNSUpstreamOptions builds Options for private-rdns upstreams.  insecure
// must match the standalone --insecure / Insecure flag used for primary upstreams.
func privateRDNSUpstreamOptions(
	l *slog.Logger,
	httpVersions []upstream.HTTPVersion,
	boot upstream.Resolver,
	insecure bool,
	timeout time.Duration,
) (opts *upstream.Options) {
	return &upstream.Options{
		Logger:             l,
		HTTPVersions:       httpVersions,
		InsecureSkipVerify: insecure,
		Bootstrap:          boot,
		Timeout:            min(defaultLocalTimeout, timeout),
	}
}

// initBootstrap initializes the [upstream.Resolver] for bootstrapping upstream
// servers.  It returns the default resolver if no bootstraps were specified.
// The returned resolver will also use system hosts files first.
func initBootstrap(
	ctx context.Context,
	l *slog.Logger,
	bootstraps []string,
	opts *upstream.Options,
) (r upstream.Resolver, err error) {
	var resolvers []upstream.Resolver

	for i, b := range bootstraps {
		var ur *upstream.UpstreamResolver
		ur, err = upstream.NewUpstreamResolver(b, opts)
		if err != nil {
			return nil, fmt.Errorf("creating bootstrap resolver at index %d: %w", i, err)
		}

		resolvers = append(resolvers, upstream.NewCachingResolver(ur))
	}

	switch len(resolvers) {
	case 0:
		etcHosts, hostsErr := upstream.NewDefaultHostsResolver(ctx, osutil.RootDirFS(), l)
		if hostsErr != nil {
			l.ErrorContext(ctx, "creating default hosts resolver", slogutil.KeyError, hostsErr)

			return net.DefaultResolver, nil
		}

		return upstream.ConsequentResolver{etcHosts, net.DefaultResolver}, nil
	case 1:
		return resolvers[0], nil
	default:
		return upstream.ParallelResolver(resolvers), nil
	}
}

// initEDNS inits EDNS-related config fields.
func (conf *configuration) initEDNS(
	ctx context.Context,
	l *slog.Logger,
	config *proxy.Config,
) (err error) {
	if conf.EDNSAddr == "" {
		return nil
	}

	if !conf.EnableEDNSSubnet {
		l.WarnContext(ctx, "--edns is required", "--edns-addr", conf.EDNSAddr)

		return nil
	}

	config.EDNSAddr, err = netutil.ParseIP(conf.EDNSAddr)
	if err != nil {
		return fmt.Errorf("parsing edns-addr: %w", err)
	}

	return nil
}

// initBogusNXDomain inits BogusNXDomain structure.
func (conf *configuration) initBogusNXDomain(
	ctx context.Context,
	l *slog.Logger,
	config *proxy.Config,
) {
	if len(conf.BogusNXDomain) == 0 {
		return
	}

	for i, s := range conf.BogusNXDomain {
		p, err := proxynetutil.ParseSubnet(s)
		if err != nil {
			// TODO(a.garipov): Consider returning this err as a proper error.
			l.WarnContext(ctx, "parsing bogus nxdomain", "index", i, slogutil.KeyError, err)
		} else {
			config.BogusNXDomain = append(config.BogusNXDomain, p)
		}
	}
}

// initTLSConfig inits the TLS config.
func (conf *configuration) initTLSConfig(config *proxy.Config) (err error) {
	if conf.TLSCertPath != "" && conf.TLSKeyPath != "" {
		var tlsConfig *tls.Config
		tlsConfig, err = newTLSConfig(conf)
		if err != nil {
			return fmt.Errorf("loading TLS config: %w", err)
		}

		config.TLSConfig = tlsConfig
	}

	return nil
}

// initDNSCryptConfig inits the DNSCrypt config.  config must not be nil.
func (conf *configuration) initDNSCryptConfig(config *proxy.Config) (err error) {
	if conf.DNSCryptConfigPath == "" {
		return nil
	}

	b, err := os.ReadFile(conf.DNSCryptConfigPath)
	if err != nil {
		return fmt.Errorf("reading dnscrypt config %q: %w", conf.DNSCryptConfigPath, err)
	}

	rc := &dnscrypt.ResolverConfig{}
	err = yaml.Unmarshal(b, rc)
	if err != nil {
		return fmt.Errorf("unmarshalling dnscrypt config: %w", err)
	}

	err = rc.Validate()
	if err != nil {
		return fmt.Errorf("validating dnscrypt config: %w", err)
	}

	cert, err := rc.NewCert()
	if err != nil {
		return fmt.Errorf("creating dnscrypt certificate: %w", err)
	}

	err = cert.Validate()
	if err != nil {
		return fmt.Errorf("validating dnscrypt certificate: %w", err)
	}

	config.DNSCryptResolverCert = cert
	config.DNSCryptProviderName = rc.ProviderName

	return nil
}

// parseListenAddrs returns a slice of listen IP addresses from the given
// options.  In case no addresses are specified by options returns a slice with
// the IPv4 unspecified address "0.0.0.0".
//
// TODO(d.kolyshev): Join errors.
func parseListenAddrs(addrStrs []string) (addrs []netip.Addr, err error) {
	for i, a := range addrStrs {
		var ip netip.Addr
		ip, err = netip.ParseAddr(a)
		if err != nil {
			return addrs, fmt.Errorf("parsing listen address at index %d: %s", i, a)
		}

		addrs = append(addrs, ip)
	}

	if len(addrs) == 0 {
		// If ListenAddrs has not been parsed through config file nor command
		// line we set it to "0.0.0.0".
		//
		// TODO(a.garipov): Consider using localhost.
		addrs = append(addrs, netip.IPv4Unspecified())
	}

	return addrs, nil
}

// initListenAddrs sets up proxy configuration listen IP addresses.
func (conf *configuration) initListenAddrs(config *proxy.Config) (err error) {
	addrs, err := parseListenAddrs(conf.ListenAddrs)
	if err != nil {
		return fmt.Errorf("parsing listen addresses: %w", err)
	}

	if len(conf.ListenPorts) == 0 {
		// If ListenPorts has not been parsed through config file nor command
		// line we set it to 53.
		conf.ListenPorts = []uint16{53}
	}

	for _, port := range conf.ListenPorts {
		for _, ip := range addrs {
			addrPort := netip.AddrPortFrom(ip, port)

			config.UDPListenAddr = append(config.UDPListenAddr, net.UDPAddrFromAddrPort(addrPort))
			config.TCPListenAddr = append(config.TCPListenAddr, net.TCPAddrFromAddrPort(addrPort))
		}
	}

	if config.TLSConfig != nil {
		initTLSListenAddrs(config, conf, addrs)
	}

	if config.DNSCryptResolverCert != nil && config.DNSCryptProviderName != "" {
		initDNSCryptListenAddrs(config, conf, addrs)
	}

	return nil
}

// initTLSListenAddrs sets up proxy configuration TLS listen addresses.  conf,
// proxyConf must not be nil.  If conf.HTTPSListenPorts is not empty,
// proxyConf.HTTPConfig must not be nil.
func initTLSListenAddrs(proxyConf *proxy.Config, conf *configuration, addrs []netip.Addr) {
	httpConfig := proxyConf.HTTPConfig
	for _, ip := range addrs {
		for _, port := range conf.TLSListenPorts {
			a := net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, port))
			proxyConf.TLSListenAddr = append(proxyConf.TLSListenAddr, a)
		}

		for _, port := range conf.HTTPSListenPorts {
			a := netip.AddrPortFrom(ip, port)
			httpConfig.ListenAddresses = append(httpConfig.ListenAddresses, a)
		}

		for _, port := range conf.QUICListenPorts {
			a := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port))
			proxyConf.QUICListenAddr = append(proxyConf.QUICListenAddr, a)
		}
	}
}

// initDNSCryptListenAddrs sets up proxy configuration DNSCrypt listen
// addresses.  proxyConf and conf must not be nil.
func initDNSCryptListenAddrs(proxyConf *proxy.Config, conf *configuration, addrs []netip.Addr) {
	for _, port := range conf.DNSCryptListenPorts {
		for _, ip := range addrs {
			addrPort := netip.AddrPortFrom(ip, port)

			tcp := net.TCPAddrFromAddrPort(addrPort)
			proxyConf.DNSCryptTCPListenAddr = append(proxyConf.DNSCryptTCPListenAddr, tcp)

			udp := net.UDPAddrFromAddrPort(addrPort)
			proxyConf.DNSCryptUDPListenAddr = append(proxyConf.DNSCryptUDPListenAddr, udp)
		}
	}
}

// initSubnets sets the DNS64 configuration into conf.
//
// TODO(d.kolyshev): Join errors.
func (conf *configuration) initSubnets(proxyConf *proxy.Config) (err error) {
	if proxyConf.UseDNS64 = conf.DNS64; proxyConf.UseDNS64 {
		for i, p := range conf.DNS64Prefix {
			var pref netip.Prefix
			pref, err = netip.ParsePrefix(p)
			if err != nil {
				return fmt.Errorf("parsing dns64 prefix at index %d: %w", i, err)
			}

			proxyConf.DNS64Prefs = append(proxyConf.DNS64Prefs, pref)
		}
	}

	if !conf.UsePrivateRDNS {
		return nil
	}

	return conf.initPrivateSubnets(proxyConf)
}

// initSubnets sets the private subnets configuration into conf.
func (conf *configuration) initPrivateSubnets(proxyConf *proxy.Config) (err error) {
	private := make([]netip.Prefix, 0, len(conf.PrivateSubnets))
	for i, p := range conf.PrivateSubnets {
		var pref netip.Prefix
		pref, err = netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("parsing private subnet at index %d: %w", i, err)
		}

		private = append(private, pref)
	}

	if len(private) > 0 {
		proxyConf.PrivateSubnets = netutil.SliceSubnetSet(private)
	}

	return nil
}

// loadServersList loads a list of DNS servers from the specified list.  The
// thing is that the user may specify either a server address or the path to a
// file with a list of addresses.  This method takes care of it, it reads the
// file and loads servers from this file if needed.  An existing path that
// cannot be read as a list file is an error; a missing path is treated as a
// server address.
// loadNamedServersList loads a servers list and wraps load errors with what.
func loadNamedServersList(sources []string, what string) (servers []string, err error) {
	servers, err = loadServersList(sources)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", what, err)
	}

	return servers, nil
}

func loadServersList(sources []string) (servers []string, err error) {
	for _, source := range sources {
		var added []string
		added, err = appendServersFromSource(source)
		if err != nil {
			return nil, err
		}

		servers = append(servers, added...)
	}

	return servers, nil
}

// appendServersFromSource treats source as a file path when it exists, or as a
// literal server address when the path does not exist.  Other read/stat errors
// are returned.
func appendServersFromSource(source string) (added []string, err error) {
	// #nosec G304 -- Trust the file path that is given in the configuration.
	data, readErr := os.ReadFile(source)
	if readErr != nil {
		return serversFromReadError(source, readErr)
	}

	return parseServerFileLines(string(data)), nil
}

// serversFromReadError decides whether a failed ReadFile means a literal
// address (path does not exist) or a hard error (stat/read failure).
func serversFromReadError(source string, readErr error) (added []string, err error) {
	_, statErr := os.Stat(source)
	if errors.Is(statErr, os.ErrNotExist) {
		return []string{source}, nil
	}

	if statErr != nil {
		return nil, fmt.Errorf("accessing servers list %q: %w", source, statErr)
	}

	return nil, fmt.Errorf("reading servers list %q: %w", source, readErr)
}

// parseServerFileLines returns non-empty, non-comment lines from a servers
// list file body.
func parseServerFileLines(data string) (servers []string) {
	// TODO(a.garipov):  Be smarter about bytes vs. strings.
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)

		// Ignore comments in the file.
		if line == "" ||
			strings.HasPrefix(line, "!") ||
			strings.HasPrefix(line, "#") {
			continue
		}

		servers = append(servers, line)
	}

	return servers
}

// initTrustedProxies sets TrustedProxies from configuration.  Empty means no
// peer is trusted for DoH forwarding headers or Proxy Protocol v2.  A /0
// prefix is still accepted but emits a Warn: it restores header/PPv2 spoofing
// for any direct peer.
func (conf *configuration) initTrustedProxies(
	l *slog.Logger,
	proxyConf *proxy.Config,
) (err error) {
	if len(conf.TrustedProxies) == 0 {
		proxyConf.TrustedProxies = netutil.SliceSubnetSet{}

		return nil
	}

	trusted := make([]netip.Prefix, 0, len(conf.TrustedProxies))
	for i, s := range conf.TrustedProxies {
		var pref netip.Prefix
		pref, err = proxynetutil.ParseSubnet(s)
		if err != nil {
			return fmt.Errorf("parsing trusted proxy at index %d: %w", i, err)
		}

		trusted = append(trusted, pref)
	}

	proxyConf.TrustedProxies = netutil.SliceSubnetSet(trusted)
	warnTrustedProxiesWideOpen(l, trusted)

	return nil
}

// warnTrustedProxiesWideOpen logs when any configured prefix is /0
// (0.0.0.0/0 or ::/0).
func warnTrustedProxiesWideOpen(l *slog.Logger, trusted []netip.Prefix) {
	var wide []string
	for _, pref := range trusted {
		if pref.Bits() == 0 {
			wide = append(wide, pref.String())
		}
	}
	if len(wide) == 0 {
		return
	}

	l.Warn(
		"trusted-proxies contains a /0 prefix; any direct peer can forge "+
			"DoH client-IP headers and Proxy Protocol v2; set trusted-proxies "+
			"to real load-balancer CIDRs instead",
		"prefixes", wide,
	)
}

// hostsFiles returns the list of hosts files to resolve from.  It's empty if
// resolving from hosts files is disabled.
func (conf *configuration) hostsFiles(
	ctx context.Context,
	l *slog.Logger,
) (paths []string, err error) {
	if !conf.HostsFileEnabled {
		l.DebugContext(ctx, "hosts files are disabled")

		return nil, nil
	}

	l.DebugContext(ctx, "hosts files are enabled")

	if len(conf.HostsFiles) > 0 {
		return conf.HostsFiles, nil
	}

	paths, err = proxynetutil.DefaultHostsPaths()
	if err != nil {
		return nil, fmt.Errorf("getting default hosts files: %w", err)
	}

	l.DebugContext(ctx, "hosts files are not specified, using default", "paths", paths)

	return paths, nil
}
