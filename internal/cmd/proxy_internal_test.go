package cmd

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/fcchbjm/dnsproxy/ratelimit"
	"github.com/fcchbjm/dnsproxy/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateRDNSUpstreamOptions_insecure(t *testing.T) {
	t.Parallel()

	l := slogutil.NewDiscardLogger()
	timeout := 5 * time.Second

	t.Run("inherits_true", func(t *testing.T) {
		t.Parallel()

		opts := privateRDNSUpstreamOptions(l, upstream.DefaultHTTPVersions, nil, true, timeout)
		require.NotNil(t, opts)
		assert.True(t, opts.InsecureSkipVerify)
		assert.Equal(t, defaultLocalTimeout, opts.Timeout)
	})

	t.Run("inherits_false", func(t *testing.T) {
		t.Parallel()

		opts := privateRDNSUpstreamOptions(l, upstream.DefaultHTTPVersions, nil, false, timeout)
		require.NotNil(t, opts)
		assert.False(t, opts.InsecureSkipVerify)
	})

	t.Run("caps_timeout", func(t *testing.T) {
		t.Parallel()

		opts := privateRDNSUpstreamOptions(l, upstream.DefaultHTTPVersions, nil, false, 100*time.Millisecond)
		require.NotNil(t, opts)
		assert.Equal(t, 100*time.Millisecond, opts.Timeout)
	})
}

func TestCreateProxyConfig_TLSTimeout(t *testing.T) {
	t.Parallel()

	l := slogutil.NewDiscardLogger()
	ctx := context.Background()

	t.Run("standalone_default", func(t *testing.T) {
		t.Parallel()

		conf := newDefaultConfiguration()
		assert.Equal(t, defaultTLSTimeout, time.Duration(conf.TLSTimeout))
		assert.Equal(t, 60*time.Second, time.Duration(conf.TLSTimeout))
		assert.Equal(t, uint(64), conf.RatelimitSubnetLenIPv6)
		assert.Equal(t, uint(ratelimit.DefaultMaxSize), conf.RatelimitMaxSize)

		// Fields required for createProxyConfig; do not override TLSTimeout.
		conf.HostsFileEnabled = false
		conf.ListenAddrs = []string{"127.0.0.1"}
		conf.ListenPorts = []uint16{0}
		conf.Upstreams = []string{"127.0.0.1:53"}

		proxyConf, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		require.NotNil(t, proxyConf)
		assert.Equal(t, defaultTLSTimeout, proxyConf.TLSTimeout)
	})

	t.Run("custom_shorter", func(t *testing.T) {
		t.Parallel()

		custom := 30 * time.Second
		conf := newDefaultConfiguration()
		conf.HostsFileEnabled = false
		conf.ListenAddrs = []string{"127.0.0.1"}
		conf.ListenPorts = []uint16{0}
		conf.Upstreams = []string{"127.0.0.1:53"}
		conf.TLSTimeout = timeutil.Duration(custom)

		proxyConf, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		require.NotNil(t, proxyConf)
		assert.Equal(t, custom, proxyConf.TLSTimeout)
	})
}

func TestLoadServersList(t *testing.T) {
	t.Parallel()

	t.Run("missing_path_as_address", func(t *testing.T) {
		t.Parallel()

		addr := "127.0.0.1:53"
		servers, err := loadServersList([]string{addr})
		require.NoError(t, err)
		assert.Equal(t, []string{addr}, servers)
	})

	t.Run("existing_file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		path := filepath.Join(dir, "upstreams.txt")
		content := "1.1.1.1:53\n# comment\n8.8.8.8:53\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		servers, err := loadServersList([]string{path})
		require.NoError(t, err)
		assert.Equal(t, []string{"1.1.1.1:53", "8.8.8.8:53"}, servers)
	})

	t.Run("existing_directory_errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		servers, err := loadServersList([]string{dir})
		require.Error(t, err)
		assert.Nil(t, servers)
		assert.Contains(t, err.Error(), "reading servers list")
	})
}

const warnOptimisticHostsCombo = "cache-optimistic with hosts-file-enabled"

func TestCreateProxyConfig_optimisticHostsWarn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	baseConf := func(tb testing.TB) (conf *configuration) {
		tb.Helper()

		hostsPath := filepath.Join(tb.TempDir(), "hosts")
		require.NoError(tb, os.WriteFile(hostsPath, []byte{}, 0o600))

		conf = newDefaultConfiguration()
		conf.HostsFileEnabled = false
		conf.CacheOptimistic = false
		conf.ListenAddrs = []string{"127.0.0.1"}
		conf.ListenPorts = []uint16{0}
		conf.Upstreams = []string{"127.0.0.1:53"}
		conf.HostsFiles = []string{hostsPath}

		return conf
	}

	t.Run("both_enabled_warns", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		conf := baseConf(t)
		conf.HostsFileEnabled = true
		conf.CacheOptimistic = true

		_, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		assert.Contains(t, logBuf.String(), warnOptimisticHostsCombo)
	})

	t.Run("optimistic_only_no_combo_warn", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		conf := baseConf(t)
		conf.HostsFileEnabled = false
		conf.CacheOptimistic = true

		_, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		assert.NotContains(t, logBuf.String(), warnOptimisticHostsCombo)
	})

	t.Run("hosts_only_no_combo_warn", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		conf := baseConf(t)
		conf.HostsFileEnabled = true
		conf.CacheOptimistic = false

		_, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		assert.NotContains(t, logBuf.String(), warnOptimisticHostsCombo)
	})
}

const warnTrustedProxiesWideOpenMsg = "trusted-proxies contains a /0 prefix"

func TestCreateProxyConfig_trustedProxiesWideOpenWarn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	baseConf := func(tb testing.TB) (conf *configuration) {
		tb.Helper()

		conf = newDefaultConfiguration()
		conf.HostsFileEnabled = false
		conf.ListenAddrs = []string{"127.0.0.1"}
		conf.ListenPorts = []uint16{0}
		conf.Upstreams = []string{"127.0.0.1:53"}
		conf.TrustedProxies = nil

		return conf
	}

	t.Run("v4_slash_zero_warns", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		conf := baseConf(t)
		conf.TrustedProxies = []string{"0.0.0.0/0"}

		proxyConf, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		assert.Contains(t, logBuf.String(), warnTrustedProxiesWideOpenMsg)
		require.NotNil(t, proxyConf.TrustedProxies)
		assert.True(t, proxyConf.TrustedProxies.Contains(netip.MustParseAddr("8.8.8.8")))
	})

	t.Run("v6_slash_zero_warns", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		conf := baseConf(t)
		conf.TrustedProxies = []string{"::/0"}

		proxyConf, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		assert.Contains(t, logBuf.String(), warnTrustedProxiesWideOpenMsg)
		require.NotNil(t, proxyConf.TrustedProxies)
		assert.True(t, proxyConf.TrustedProxies.Contains(netip.MustParseAddr("2001:db8::1")))
	})

	t.Run("v4_and_v6_slash_zero_one_warn", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		conf := baseConf(t)
		conf.TrustedProxies = []string{"0.0.0.0/0", "::/0"}

		proxyConf, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		logText := logBuf.String()
		assert.Equal(t, 1, strings.Count(logText, warnTrustedProxiesWideOpenMsg))
		require.NotNil(t, proxyConf.TrustedProxies)
		assert.True(t, proxyConf.TrustedProxies.Contains(netip.MustParseAddr("1.2.3.4")))
		assert.True(t, proxyConf.TrustedProxies.Contains(netip.MustParseAddr("2001:db8::2")))
	})

	t.Run("empty_no_warn", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		conf := baseConf(t)
		conf.TrustedProxies = []string{}

		_, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		assert.NotContains(t, logBuf.String(), warnTrustedProxiesWideOpenMsg)
	})

	t.Run("loopback_only_no_warn", func(t *testing.T) {
		t.Parallel()

		logBuf := &bytes.Buffer{}
		l := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		conf := baseConf(t)
		conf.TrustedProxies = []string{"127.0.0.0/8"}

		_, err := createProxyConfig(ctx, l, conf)
		require.NoError(t, err)
		assert.NotContains(t, logBuf.String(), warnTrustedProxiesWideOpenMsg)
	})
}
