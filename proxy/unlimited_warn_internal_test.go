package proxy

import (
	"bytes"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	warnMaxTCPUnlimited = "max tcp connections is unlimited"
	warnMaxDoHUnlimited = "max doh concurrent requests is unlimited"
)

func newCapturingLogger(buf *bytes.Buffer) (l *slog.Logger) {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

func TestProxy_unlimitedCaps_warnOnListen(t *testing.T) {
	t.Parallel()

	t.Run("tcp_zero_warns", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		p := mustNew(t, &Config{
			Logger:            newCapturingLogger(logBuf),
			TCPListenAddr:     []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
			UpstreamConfig:    newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
			TrustedProxies:    defaultTrustedProxies,
			MaxTCPConnections: 0,
		})
		require.Nil(t, p.tcpConnsSema)
		assert.Contains(t, logBuf.String(), warnMaxTCPUnlimited)
		assert.NotContains(t, logBuf.String(), warnMaxDoHUnlimited)
	})

	t.Run("tcp_nonzero_no_unlimited_warn", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		p := mustNew(t, &Config{
			Logger:            newCapturingLogger(logBuf),
			TCPListenAddr:     []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
			UpstreamConfig:    newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
			TrustedProxies:    defaultTrustedProxies,
			MaxTCPConnections: 32,
		})
		require.NotNil(t, p.tcpConnsSema)
		logText := logBuf.String()
		assert.NotContains(t, logText, warnMaxTCPUnlimited)
		assert.True(t, strings.Contains(logText, "max tcp connections is set"), logText)
	})

	t.Run("udp_only_no_tcp_warn", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		_ = mustNew(t, &Config{
			Logger:            newCapturingLogger(logBuf),
			UDPListenAddr:     []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
			UpstreamConfig:    newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
			TrustedProxies:    defaultTrustedProxies,
			MaxTCPConnections: 0,
		})
		assert.NotContains(t, logBuf.String(), warnMaxTCPUnlimited)
		assert.NotContains(t, logBuf.String(), warnMaxDoHUnlimited)
	})

	t.Run("doh_zero_warns", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		tlsConf, _ := newTLSConfig(t)
		p := mustNew(t, &Config{
			Logger:         newCapturingLogger(logBuf),
			TLSConfig:      tlsConf,
			TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
			UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
			TrustedProxies: defaultTrustedProxies,
			HTTPConfig: &HTTPConfig{
				ListenAddresses:       []netip.AddrPort{localhostAnyPort},
				MaxConcurrentRequests: 0,
			},
		})
		require.Nil(t, p.dohReqSema)
		logText := logBuf.String()
		assert.Contains(t, logText, warnMaxDoHUnlimited)
		// TLS listen with MaxTCPConnections 0 also warns for TCP/DoT Accept.
		assert.Contains(t, logText, warnMaxTCPUnlimited)
	})

	t.Run("doh_nonzero_no_unlimited_warn", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		tlsConf, _ := newTLSConfig(t)
		p := mustNew(t, &Config{
			Logger:            newCapturingLogger(logBuf),
			TLSConfig:         tlsConf,
			TLSListenAddr:     []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
			UpstreamConfig:    newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
			TrustedProxies:    defaultTrustedProxies,
			MaxTCPConnections: 64,
			HTTPConfig: &HTTPConfig{
				ListenAddresses:       []netip.AddrPort{localhostAnyPort},
				MaxConcurrentRequests: 16,
			},
		})
		require.NotNil(t, p.dohReqSema)
		logText := logBuf.String()
		assert.NotContains(t, logText, warnMaxDoHUnlimited)
		assert.NotContains(t, logText, warnMaxTCPUnlimited)
		assert.Contains(t, logText, "max doh concurrent requests is set")
		assert.Contains(t, logText, "max tcp connections is set")
	})

	t.Run("doh_handler_only_warns", func(t *testing.T) {
		t.Parallel()

		// HTTPConfig without ListenAddresses still enables ServeHTTP; unlimited
		// concurrent DoH must warn the same as built-in HTTPS listeners.
		logBuf := &bytes.Buffer{}
		_ = mustNew(t, &Config{
			Logger:         newCapturingLogger(logBuf),
			UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
			UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
			TrustedProxies: defaultTrustedProxies,
			HTTPConfig: &HTTPConfig{
				MaxConcurrentRequests: 0,
			},
		})
		logText := logBuf.String()
		assert.Contains(t, logText, warnMaxDoHUnlimited)
		assert.NotContains(t, logText, warnMaxTCPUnlimited)
	})
}
