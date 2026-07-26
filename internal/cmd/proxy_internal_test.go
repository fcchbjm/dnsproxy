package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
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
