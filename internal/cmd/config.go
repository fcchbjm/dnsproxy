package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/fcchbjm/dnsproxy/proxy"
	"github.com/fcchbjm/dnsproxy/ratelimit"
	"gopkg.in/yaml.v3"
)

// configuration represents dnsproxy configuration.
type configuration struct {
	// ConfigPath is the path to the configuration file.
	ConfigPath string

	// LogOutput is the path to the log file.
	LogOutput string `yaml:"output"`

	// TLSCertPath is the path to the .crt with the certificate chain.
	TLSCertPath string `yaml:"tls-crt"`

	// TLSKeyPath is the path to the file with the private key.
	TLSKeyPath string `yaml:"tls-key"`

	// HTTPSServerName sets Server header for the HTTPS server.
	HTTPSServerName string `yaml:"https-server-name"`

	// HTTPSUserinfo is the sole permitted userinfo for the DoH basic
	// authentication.  If it is set, all DoH queries are required to have this
	// basic authentication information.
	HTTPSUserinfo string `yaml:"https-userinfo"`

	// DNSCryptConfigPath is the path to the DNSCrypt configuration file.
	DNSCryptConfigPath string `yaml:"dnscrypt-config"`

	// EDNSAddr is the custom EDNS Client Address to send.
	EDNSAddr string `yaml:"edns-addr"`

	// UpstreamMode determines the logic through which upstreams will be used.
	// If not specified the [proxy.UpstreamModeLoadBalance] is used.
	UpstreamMode string `yaml:"upstream-mode"`

	// ListenAddrs is the list of server's listen addresses.
	ListenAddrs []string `yaml:"listen-addrs"`

	// DoHRoutes is the list of routes for DNS-over-HTTPS.  It must be a slice
	// of valid route patterns, if it is empty, the default routes are
	// registered.
	DoHRoutes []string `yaml:"doh-routes"`

	// ListenPorts are the ports server listens on for plain DNS.
	ListenPorts []uint16 `yaml:"listen-ports"`

	// HTTPSListenPorts are the ports server listens on for DNS-over-HTTPS.
	HTTPSListenPorts []uint16 `yaml:"https-port"`

	// TLSListenPorts are the ports server listens on for DNS-over-TLS.
	TLSListenPorts []uint16 `yaml:"tls-port"`

	// QUICListenPorts are the ports server listens on for DNS-over-QUIC.
	QUICListenPorts []uint16 `yaml:"quic-port"`

	// DNSCryptListenPorts are the ports server listens on for DNSCrypt.
	DNSCryptListenPorts []uint16 `yaml:"dnscrypt-port"`

	// Upstreams is the list of DNS upstream servers.
	Upstreams []string `yaml:"upstream"`

	// BootstrapDNS is the list of bootstrap DNS upstream servers.
	BootstrapDNS []string `yaml:"bootstrap"`

	// Fallbacks is the list of fallback DNS upstream servers.
	Fallbacks []string `yaml:"fallback"`

	// PrivateRDNSUpstreams are upstreams to use for reverse DNS lookups of
	// private addresses, including the requests for authority records, such as
	// SOA and NS.
	PrivateRDNSUpstreams []string `yaml:"private-rdns-upstream"`

	// DNS64Prefix defines the DNS64 prefixes that dnsproxy should use when it
	// acts as a DNS64 server.  If not specified, dnsproxy uses the default
	// Well-Known Prefix.  This option can be specified multiple times.
	DNS64Prefix []string `yaml:"dns64-prefix"`

	// PrivateSubnets is the list of private subnets to determine private
	// addresses.
	PrivateSubnets []string `yaml:"private-subnets"`

	// TrustedProxies is the list of CIDR networks whose direct peers may supply
	// trusted client identity via DoH forwarding headers or Proxy Protocol v2.
	// Empty (the default) means no peer is trusted.
	TrustedProxies []string `yaml:"trusted-proxies"`

	// BogusNXDomain transforms responses that contain at least one of the given
	// IP addresses into NXDOMAIN.
	//
	// TODO(a.garipov): Find a way to use [netutil.Prefix].  Currently, package
	// go-flags doesn't support text unmarshalers.
	BogusNXDomain []string `yaml:"bogus-nxdomain"`

	// HostsFiles is the list of paths to the hosts files to resolve from.
	HostsFiles []string `yaml:"hosts-files"`

	// Timeout for outbound DNS queries to remote upstream servers in a
	// human-readable form.  Default is 10s.
	Timeout timeutil.Duration `yaml:"timeout"`

	// CacheMinTTL is the minimum TTL value for caching DNS entries, in seconds.
	// It overrides the TTL value from the upstream server, if the one is less.
	CacheMinTTL uint32 `yaml:"cache-min-ttl"`

	// CacheMaxTTL is the maximum TTL value for caching DNS entries, in seconds.
	// It overrides the TTL value from the upstream server, if the one is
	// greater.
	CacheMaxTTL uint32 `yaml:"cache-max-ttl"`

	// OptimisticAnswerTTL is the default TTL for expired cached responses
	// in seconds.
	OptimisticAnswerTTL timeutil.Duration `yaml:"optimistic-answer-ttl"`

	// OptimisticMaxAge is the maximum time entries remain in the cache
	// when cache is optimistic.
	OptimisticMaxAge timeutil.Duration `yaml:"optimistic-max-age"`

	// CacheSizeBytes is the cache size in bytes.  Default is 64k.
	CacheSizeBytes int `yaml:"cache-size"`

	// Ratelimit is the maximum number of requests per second.  Applies to UDP
	// (ProtoUDP) only; DoH, DoT, and plain TCP DNS are not limited by this
	// value.
	Ratelimit uint `yaml:"ratelimit"`

	// RatelimitSubnetLenIPv4 is a subnet length for IPv4 addresses used for
	// rate limiting requests.
	RatelimitSubnetLenIPv4 uint `yaml:"ratelimit-subnet-len-ipv4"`

	// RatelimitSubnetLenIPv6 is a subnet length for IPv6 addresses used for
	// rate limiting requests.
	RatelimitSubnetLenIPv6 uint `yaml:"ratelimit-subnet-len-ipv6"`

	// RatelimitMaxSize is the maximum number of per-subnet UDP rate-limit
	// buckets.  When full, the oldest bucket is evicted.  Applies only when
	// Ratelimit is positive.  Standalone default is 10000.
	RatelimitMaxSize uint `yaml:"ratelimit-max-size"`

	// UDPBufferSize is the size of the UDP buffer in bytes.  A value <= 0 will
	// use the system default.
	UDPBufferSize int `yaml:"udp-buf-size"`

	// MaxGoRoutines is the maximum number of goroutines.
	MaxGoRoutines uint `yaml:"max-go-routines"`

	// MaxTCPConnections is the maximum number of concurrently accepted TCP/DoT
	// connections.  Zero means unlimited (default).
	MaxTCPConnections uint `yaml:"max-tcp-connections"`

	// TLSMinVersion is the minimum allowed version of TLS.  When unset (0),
	// standalone listeners default to TLS 1.2.
	//
	// TODO(d.kolyshev): Use more suitable type.
	TLSMinVersion float32 `yaml:"tls-min-version"`

	// TLSMaxVersion is the maximum allowed version of TLS.
	//
	// TODO(d.kolyshev): Use more suitable type.
	TLSMaxVersion float32 `yaml:"tls-max-version"`

	// DoHInsecureEnabled controls whether unencrypted HTTP DoH (plain HTTP to
	// the DoH listener) is allowed.  It does not skip TLS certificate
	// verification; that is controlled by Insecure / --insecure.
	DoHInsecureEnabled bool `yaml:"doh-insecure-enabled"`

	// DoHMaxConcurrent is the maximum number of in-flight DoH requests.  Zero
	// means unlimited (default).
	DoHMaxConcurrent uint `yaml:"doh-max-concurrent"`

	// help, if true, prints the command-line option help message and quit with
	// a successful exit-code.
	help bool

	// HostsFileEnabled controls whether hosts files are used for resolving or
	// not.
	HostsFileEnabled bool `yaml:"hosts-file-enabled"`

	// Pprof defines whether the pprof information needs to be exposed via
	// localhost:6060 or not.
	Pprof bool `yaml:"pprof"`

	// Version, if true, prints the program version, and exits.
	Version bool `yaml:"version"`

	// Verbose controls the verbosity of the output.
	Verbose bool `yaml:"verbose"`

	// Insecure disables upstream servers TLS certificate verification for
	// bootstrap, primary, fallback, and private-rdns upstreams.
	Insecure bool `yaml:"insecure"`

	// IPv6Disabled makes the server to respond with NODATA to all AAAA queries.
	IPv6Disabled bool `yaml:"ipv6-disabled"`

	// HTTP3 controls whether HTTP/3 is enabled for this instance of dnsproxy.
	// It enables HTTP/3 support for both the DoH upstreams and the DoH server.
	HTTP3 bool `yaml:"http3"`

	// CacheOptimistic, if set to true, enables the optimistic DNS cache. That
	// means that cached results will be served even if their cache TTL has
	// already expired.
	CacheOptimistic bool `yaml:"cache-optimistic"`

	// Cache controls whether DNS responses are cached or not.
	Cache bool `yaml:"cache"`

	// RefuseAny makes the server to refuse requests of type ANY.
	RefuseAny bool `yaml:"refuse-any"`

	// DNSSECEnabled defines whether the proxy should set the DO bits in the
	// upstream requests.
	DNSSECEnabled bool `yaml:"dnssec"`

	// EnableEDNSSubnet uses EDNS Client Subnet extension.
	EnableEDNSSubnet bool `yaml:"edns"`

	// PendingRequestsEnabled controls whether the server should track duplicate
	// queries and only send the first of them to the upstream server.  It is
	// used to mitigate the cache poisoning attacks.
	PendingRequestsEnabled bool `yaml:"pending-requests-enabled"`

	// DNS64 defines whether DNS64 functionality is enabled or not.
	DNS64 bool `yaml:"dns64"`

	// UsePrivateRDNS makes the server to use private upstreams for reverse DNS
	// lookups of private addresses, including the requests for authority
	// records, such as SOA and NS.
	UsePrivateRDNS bool `yaml:"use-private-rdns"`

	// TCPProxyProtocolV2Enabled defines whether plain DNS-over-TCP listeners
	// require Proxy Protocol v2 headers.
	TCPProxyProtocolV2Enabled bool `yaml:"tcp-proxy-protocol-v2"`

	// TLSProxyProtocolV2Enabled defines whether DNS-over-TLS listeners require
	// Proxy Protocol v2 headers before TLS handshake.
	TLSProxyProtocolV2Enabled bool `yaml:"tls-proxy-protocol-v2"`

	// ProxyProtocolV2ReadTimeout bounds how long dnsproxy waits for an incoming
	// PPv2 preface and payload after accepting a TCP/TLS connection.
	ProxyProtocolV2ReadTimeout timeutil.Duration `yaml:"proxy-protocol-v2-read-timeout"`

	// TLSTimeout is the DoT handshake and idle read timeout.  Standalone
	// default is 60s (see parseConfig).  Zero is not meaningful here because
	// createProxyConfig always passes the configured duration into proxy.Config.
	TLSTimeout timeutil.Duration `yaml:"tls-timeout"`
}

// newDefaultConfiguration returns standalone dnsproxy defaults before CLI/YAML
// overrides.  Zero-value fields that are intentionally unlimited (e.g. future
// connection caps) stay unset here.
func newDefaultConfiguration() (conf *configuration) {
	return &configuration{
		HTTPSServerName:            "dnsproxy",
		UpstreamMode:               string(proxy.UpstreamModeLoadBalance),
		CacheSizeBytes:             64 * 1024,
		MaxGoRoutines:              32,
		Timeout:                    timeutil.Duration(10 * time.Second),
		OptimisticAnswerTTL:        timeutil.Duration(proxy.DefaultOptimisticAnswerTTL),
		OptimisticMaxAge:           timeutil.Duration(proxy.DefaultOptimisticMaxAge),
		RatelimitSubnetLenIPv4:     24,
		RatelimitSubnetLenIPv6:     64,
		RatelimitMaxSize:           ratelimit.DefaultMaxSize,
		DNSSECEnabled:              true,
		HostsFileEnabled:           true,
		PendingRequestsEnabled:     true,
		ProxyProtocolV2ReadTimeout: timeutil.Duration(3 * time.Second),
		// Standalone DoT default is intentionally shorter than library
		// [proxy.DefaultTLSTimeout] (600s) to limit idle connection occupancy.
		TLSTimeout: timeutil.Duration(defaultTLSTimeout),
	}
}

// parseConfig returns options parsed from the command args or config file.  If
// no options have been parsed, it returns a suitable exit code and an error.
func parseConfig() (conf *configuration, exitCode int, err error) {
	conf = newDefaultConfiguration()

	err = parseCmdLineOptions(conf)
	exitCode, needExit := processCmdLineOptions(conf, err)
	if needExit {
		return nil, exitCode, err
	}

	confPath := conf.ConfigPath
	if confPath == "" {
		return conf, exitCode, nil
	}

	// TODO(d.kolyshev): Bootstrap and use slog.
	fmt.Printf("dnsproxy config path: %s\n", confPath)

	err = parseConfigFile(conf, confPath)
	if err != nil {
		return nil, osutil.ExitCodeFailure, fmt.Errorf(
			"parsing config file %s: %w",
			confPath,
			err,
		)
	}

	// Parse command-line args again as it has priority over YAML config.
	err = parseCmdLineOptions(conf)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, osutil.ExitCodeFailure, err
	}

	return conf, exitCode, nil
}

// parseConfigFile fills options with the settings from file read by the given
// path.
func parseConfigFile(conf *configuration, confPath string) (err error) {
	// #nosec G304 -- Trust the file path that is given in the args.
	b, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	err = yaml.Unmarshal(b, conf)
	if err != nil {
		return fmt.Errorf("unmarshalling file: %w", err)
	}

	return nil
}
