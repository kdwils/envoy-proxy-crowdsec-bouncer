package bouncer

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	remediationmocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/crowdsec"
	"github.com/kdwils/envoy-proxy-bouncer/recorder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func parseCIDROrFail(t *testing.T, cidr string) netip.Prefix {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("failed to parse CIDR %q: %v", cidr, err)
	}
	return prefix.Masked()
}

func mkCheckRequest(ip, scheme, authority, path, method, proto, body string) *auth.CheckRequest {
	return &auth.CheckRequest{
		Attributes: &auth.AttributeContext{
			Source: &auth.AttributeContext_Peer{
				Address: &core.Address{
					Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{Address: ip}},
				},
			},
			Request: &auth.AttributeContext_Request{
				Http: &auth.AttributeContext_HttpRequest{
					Headers: map[string]string{
						":scheme":    scheme,
						":authority": authority,
						":path":      path,
						":method":    method,
						"user-agent": "UT",
					},
					Protocol: proto,
					Body:     body,
				},
			},
		},
	}
}

func newMetricsService(t *testing.T) *crowdsec.MetricsService {
	t.Helper()
	collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
		APIClient:   &apiclient.ApiClient{},
		BouncerType: "test-bouncer",
		Version:     "v1.0.0",
	})
	require.NoError(t, err)
	return collector
}

func newTestBouncer(t *testing.T, cfg config.Config) *Bouncer {
	t.Helper()
	r, err := New(cfg, recorder.NewNoOp(), nil)
	require.NoError(t, err)
	return r
}

func wantParsed(ip, scheme, authority, path, method string, body []byte, protoMajor, protoMinor int) *ParsedRequest {
	return &ParsedRequest{
		IP:           ip,
		RealIP:       ip,
		ParsedRealIP: netip.MustParseAddr(ip),
		Headers: map[string]string{
			":scheme":    scheme,
			":authority": authority,
			":path":      path,
			":method":    method,
			"user-agent": "UT",
		},
		Cookies:    nil,
		URL:        url.URL{Scheme: scheme, Host: authority, Path: path},
		Method:     method,
		UserAgent:  "UT",
		Body:       body,
		ProtoMajor: protoMajor,
		ProtoMinor: protoMinor,
	}
}

func TestExtractRealIP(t *testing.T) {
	trusted := []netip.Prefix{
		parseCIDROrFail(t, "10.0.0.0/8"),
		parseCIDROrFail(t, "192.168.0.0/16"),
	}

	tests := []struct {
		name           string
		ip             string
		xff            string
		xri            string
		trustedValue   string
		trustedProxies []netip.Prefix
		want           string
	}{
		{
			name: "No headers, returns socket IP",
			ip:   "1.2.3.4",
			want: "1.2.3.4",
		},
		{
			name: "x-real-ip present and valid",
			ip:   "1.2.3.4",
			xri:  "5.6.7.8",
			want: "5.6.7.8",
		},
		{
			name: "x-real-ip present but invalid, fallback to socket IP",
			ip:   "1.2.3.4",
			xri:  "not-an-ip",
			want: "1.2.3.4",
		},
		{
			name: "x-forwarded-for, no trusted proxies, picks last valid",
			ip:   "1.2.3.4",
			xff:  "10.0.0.1, 8.8.8.8, 9.9.9.9",
			want: "9.9.9.9",
		},
		{
			name:           "x-forwarded-for, skips trusted proxies",
			ip:             "1.2.3.4",
			xff:            "10.0.0.1, 192.168.1.1, 8.8.8.8",
			trustedProxies: trusted,
			want:           "8.8.8.8",
		},
		{
			name:           "x-forwarded-for, all trusted, fallback to socket IP",
			ip:             "1.2.3.4",
			xff:            "10.0.0.1, 192.168.1.1",
			trustedProxies: trusted,
			want:           "1.2.3.4",
		},
		{
			name: "x-forwarded-for, some invalid IPs, picks valid",
			ip:   "1.2.3.4",
			xff:  "not-an-ip, 8.8.8.8",
			want: "8.8.8.8",
		},
		{
			name: "x-forwarded-for, more than 20 IPs, only last 20 considered",
			ip:   "1.2.3.4",
			xff:  "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8,9.9.9.9,10.10.10.10,11.11.11.11,12.12.12.12,13.13.13.13,14.14.14.14,15.15.15.15,16.16.16.16,17.17.17.17,18.18.18.18,19.19.19.19,20.20.20.20,21.21.21.21,22.22.22.22",
			want: "22.22.22.22",
		},
		{
			name: "x-forwarded-for with spaces",
			ip:   "1.2.3.4",
			xff:  " 10.0.0.1 , 8.8.8.8 ",
			want: "8.8.8.8",
		},
		{
			name: "x-forwarded-for, all invalid, fallback to x-real-ip",
			ip:   "1.2.3.4",
			xff:  "not-an-ip, also-bad",
			xri:  "5.5.5.5",
			want: "5.5.5.5",
		},
		{
			name: "x-forwarded-for, all invalid, fallback to socket IP",
			ip:   "1.2.3.4",
			xff:  "not-an-ip, also-bad",
			want: "1.2.3.4",
		},
		{
			name:         "trustedIPHeader set and present, used directly, bypassing x-forwarded-for entirely",
			ip:           "1.2.3.4",
			xff:          "9.9.9.9",
			trustedValue: "8.8.8.8",
			want:         "8.8.8.8",
		},
		{
			name:         "trustedIPHeader set but invalid IP, falls through to x-forwarded-for",
			ip:           "1.2.3.4",
			xff:          "9.9.9.9",
			trustedValue: "not-an-ip",
			want:         "9.9.9.9",
		},
		{
			name:         "trustedIPHeader set but absent from request, falls through to x-forwarded-for",
			ip:           "1.2.3.4",
			xff:          "9.9.9.9",
			trustedValue: "",
			want:         "9.9.9.9",
		},
		{
			name:           "IPv4-mapped IPv6 in x-forwarded-for matches IPv4 trusted prefix, falls through to socket IP",
			ip:             "1.2.3.4",
			xff:            "::ffff:1.2.3.5",
			trustedProxies: []netip.Prefix{parseCIDROrFail(t, "1.2.3.0/24")},
			want:           "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := ExtractRealIP(tt.ip, tt.xff, tt.xri, tt.trustedValue, tt.trustedProxies)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractRealIPFromHTTP(t *testing.T) {
	newReq := func(remoteAddr string, headers map[string][]string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
		require.NoError(t, err)
		req.RemoteAddr = remoteAddr
		maps.Copy(req.Header, headers)
		return req
	}

	tests := []struct {
		name            string
		remoteAddr      string
		headers         map[string][]string
		trustedProxies  []string
		trustedIPHeader string
		want            string
	}{
		{
			name:       "no headers, returns socket IP",
			remoteAddr: "1.2.3.4:5678",
			want:       "1.2.3.4",
		},
		{
			name:       "IPv6 socket IP without headers",
			remoteAddr: "[2001:db8::1]:8080",
			want:       "2001:db8::1",
		},
		{
			name:       "x-forwarded-for, no trusted proxies, picks last",
			remoteAddr: "1.2.3.4:5678",
			headers: map[string][]string{
				"X-Forwarded-For": {"10.0.0.1, 8.8.8.8, 9.9.9.9"},
			},
			want: "9.9.9.9",
		},
		{
			name:           "x-forwarded-for, skips trusted proxies",
			remoteAddr:     "1.2.3.4:5678",
			trustedProxies: []string{"10.0.0.0/8", "192.168.0.0/16"},
			headers: map[string][]string{
				"X-Forwarded-For": {"10.0.0.1, 192.168.1.1, 8.8.8.8"},
			},
			want: "8.8.8.8",
		},
		{
			name:       "x-real-ip present and valid",
			remoteAddr: "1.2.3.4:5678",
			headers: map[string][]string{
				"X-Real-IP": {"5.6.7.8"},
			},
			want: "5.6.7.8",
		},
		{
			name:           "mixed-case x-forwarded-for key is matched",
			remoteAddr:     "1.2.3.4:5678",
			trustedProxies: []string{"10.0.0.0/8", "192.168.0.0/16"},
			headers: map[string][]string{
				"X-FORWARDED-FOR": {"10.0.0.1, 8.8.8.8"},
			},
			want: "8.8.8.8",
		},
		{
			name:       "mixed-case x-real-ip key is matched",
			remoteAddr: "1.2.3.4:5678",
			headers: map[string][]string{
				"x-REAL-ip": {"5.6.7.8"},
			},
			want: "5.6.7.8",
		},
		{
			name:            "trustedIPHeader set and present, used directly, bypassing x-forwarded-for",
			remoteAddr:      "1.2.3.4:5678",
			trustedIPHeader: "x-envoy-external-address",
			headers: map[string][]string{
				"X-Envoy-External-Address": {"8.8.8.8"},
				"X-Forwarded-For":          {"9.9.9.9"},
			},
			want: "8.8.8.8",
		},
		{
			name:            "trustedIPHeader set but absent from request, falls through to x-forwarded-for",
			remoteAddr:      "1.2.3.4:5678",
			trustedIPHeader: "x-envoy-external-address",
			headers: map[string][]string{
				"X-Forwarded-For": {"9.9.9.9"},
			},
			want: "9.9.9.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBouncer(t, config.Config{TrustedProxies: tt.trustedProxies, TrustedIPHeader: tt.trustedIPHeader})
			got := b.ExtractRealIPFromHTTP(newReq(tt.remoteAddr, tt.headers))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsExemptIP(t *testing.T) {
	tests := []struct {
		name      string
		ip        netip.Addr
		exemptIPs []string
		want      bool
	}{
		{
			name:      "Empty exempt IPs list returns false",
			ip:        netip.MustParseAddr("10.0.0.1"),
			exemptIPs: nil,
			want:      false,
		},
		{
			name:      "IP in exempt IPs (IPv4)",
			ip:        netip.MustParseAddr("10.1.2.3"),
			exemptIPs: []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"},
			want:      true,
		},
		{
			name:      "IP not in exempt IPs (IPv4)",
			ip:        netip.MustParseAddr("8.8.8.8"),
			exemptIPs: []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"},
			want:      false,
		},
		{
			name:      "IP in exempt IPs (second range)",
			ip:        netip.MustParseAddr("192.168.1.100"),
			exemptIPs: []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"},
			want:      true,
		},
		{
			name:      "Invalid IP returns false",
			ip:        netip.Addr{},
			exemptIPs: []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"},
			want:      false,
		},
		{
			name:      "IPv6 in exempt IPs",
			ip:        netip.MustParseAddr("2001:db8::1"),
			exemptIPs: []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"},
			want:      true,
		},
		{
			name:      "IPv6 not in exempt IPs",
			ip:        netip.MustParseAddr("2001:dead:beef::1"),
			exemptIPs: []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"},
			want:      false,
		},
		{
			name:      "IPv4-mapped IPv6 in exempt IPs",
			ip:        netip.MustParseAddr("::ffff:10.1.2.3"),
			exemptIPs: []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBouncer(t, config.Config{ExemptIPs: tt.exemptIPs})
			got := b.isExemptIP(tt.ip)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsTrustedProxy(t *testing.T) {
	trusted := []netip.Prefix{
		parseCIDROrFail(t, "10.0.0.0/8"),
		parseCIDROrFail(t, "192.168.0.0/16"),
		parseCIDROrFail(t, "2001:db8::/32"),
	}

	tests := []struct {
		name           string
		ip             string
		trustedProxies []netip.Prefix
		want           bool
	}{
		{
			name:           "Empty trusted proxies returns false",
			ip:             "10.0.0.1",
			trustedProxies: nil,
			want:           false,
		},
		{
			name:           "IP in trusted proxies (IPv4)",
			ip:             "10.1.2.3",
			trustedProxies: trusted,
			want:           true,
		},
		{
			name:           "IP not in trusted proxies (IPv4)",
			ip:             "8.8.8.8",
			trustedProxies: trusted,
			want:           false,
		},
		{
			name:           "IP in trusted proxies (second range)",
			ip:             "192.168.1.100",
			trustedProxies: trusted,
			want:           true,
		},
		{
			name:           "Invalid IP returns false",
			ip:             "not-an-ip",
			trustedProxies: trusted,
			want:           false,
		},
		{
			name:           "IPv6 in trusted proxies",
			ip:             "2001:db8::1",
			trustedProxies: trusted,
			want:           true,
		},
		{
			name:           "IPv6 not in trusted proxies",
			ip:             "2001:dead:beef::1",
			trustedProxies: trusted,
			want:           false,
		},
		{
			name:           "IPv4-mapped IPv6 matches IPv4 trusted prefix",
			ip:             "::ffff:10.1.2.3",
			trustedProxies: trusted,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTrustedProxy(tt.ip, tt.trustedProxies)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsTrustedProxyAddr(t *testing.T) {
	trusted := []netip.Prefix{
		parseCIDROrFail(t, "10.0.0.0/8"),
		parseCIDROrFail(t, "192.168.0.0/16"),
		parseCIDROrFail(t, "2001:db8::/32"),
	}

	tests := []struct {
		name           string
		addr           netip.Addr
		trustedProxies []netip.Prefix
		want           bool
	}{
		{
			name:           "Empty trusted proxies returns false",
			addr:           netip.MustParseAddr("10.0.0.1"),
			trustedProxies: nil,
			want:           false,
		},
		{
			name:           "IPv4 addr in trusted prefix",
			addr:           netip.MustParseAddr("10.1.2.3"),
			trustedProxies: trusted,
			want:           true,
		},
		{
			name:           "IPv4 addr not in trusted prefix",
			addr:           netip.MustParseAddr("8.8.8.8"),
			trustedProxies: trusted,
			want:           false,
		},
		{
			name:           "IPv6 addr in trusted prefix",
			addr:           netip.MustParseAddr("2001:db8::1"),
			trustedProxies: trusted,
			want:           true,
		},
		{
			name:           "IPv4-mapped IPv6 matches IPv4 trusted prefix via Unmap",
			addr:           netip.MustParseAddr("::ffff:10.1.2.3"),
			trustedProxies: trusted,
			want:           true,
		},
		{
			name:           "IPv4-mapped IPv6 not in trusted prefix",
			addr:           netip.MustParseAddr("::ffff:8.8.8.8"),
			trustedProxies: trusted,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTrustedProxyAddr(tt.addr, tt.trustedProxies)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseIPNets(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		wantCIDR []string
		wantErr  bool
	}{
		{
			name:     "Empty input returns empty slice",
			input:    []string{},
			wantCIDR: []string{},
			wantErr:  false,
		},
		{
			name:     "Single IPv4 with CIDR",
			input:    []string{"10.0.0.0/8"},
			wantCIDR: []string{"10.0.0.0/8"},
			wantErr:  false,
		},
		{
			name:     "Single IPv4 without CIDR",
			input:    []string{"192.168.1.1"},
			wantCIDR: []string{"192.168.1.1/32"},
			wantErr:  false,
		},
		{
			name:     "Single IPv6 with CIDR",
			input:    []string{"2001:db8::/32"},
			wantCIDR: []string{"2001:db8::/32"},
			wantErr:  false,
		},
		{
			name:     "Single IPv6 without CIDR",
			input:    []string{"2001:db8::1"},
			wantCIDR: []string{"2001:db8::1/128"},
			wantErr:  false,
		},
		{
			name:     "Mixed IPv4 and IPv6, some with and without CIDR",
			input:    []string{"10.0.0.1", "172.16.0.0/12", "2001:db8::1", "fe80::/10"},
			wantCIDR: []string{"10.0.0.1/32", "172.16.0.0/12", "2001:db8::1/128", "fe80::/10"},
			wantErr:  false,
		},
		{
			name:     "Non-canonical CIDR with host bits set is masked to network address",
			input:    []string{"10.0.0.1/8"},
			wantCIDR: []string{"10.0.0.0/8"},
			wantErr:  false,
		},
		{
			name:     "Invalid address returns error",
			input:    []string{"not-an-ip"},
			wantCIDR: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPNets(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			gotCIDRs := make([]string, len(got))
			for i, p := range got {
				gotCIDRs[i] = p.String()
			}
			assert.Equal(t, tt.wantCIDR, gotCIDRs)
		})
	}
}

func TestParseCheckRequest(t *testing.T) {
	r := newTestBouncer(t, config.Config{TrustedProxies: []string{"10.0.0.0/8"}})

	tests := []struct {
		name string
		req  *auth.CheckRequest
		want *ParsedRequest
	}{
		{
			name: "nil request returns empty ParsedRequest",
			req:  nil,
			want: &ParsedRequest{
				IP:           "",
				RealIP:       "",
				ParsedRealIP: netip.Addr{},
				Headers:      nil,
				Cookies:      nil,
				URL:          url.URL{},
				Method:       "",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   0,
				ProtoMinor:   0,
			},
		},
		{
			name: "nil attributes returns empty ParsedRequest",
			req:  &auth.CheckRequest{},
			want: &ParsedRequest{
				IP:           "",
				RealIP:       "",
				ParsedRealIP: netip.Addr{},
				Headers:      nil,
				Cookies:      nil,
				URL:          url.URL{},
				Method:       "",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   0,
				ProtoMinor:   0,
			},
		},
		{
			name: "full request with Envoy pseudo-headers",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "5.6.7.8",
								},
							},
						},
					},
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								":scheme":         "https",
								":authority":      "example.com",
								":path":           "/foo/bar",
								":method":         "GET",
								"user-agent":      "TestAgent",
								"Some-Header":     "some-value",
								"x-forwarded-for": "10.0.0.1,5.6.7.8",
							},
							Protocol: "HTTP/1.1",
							Body:     "bodydata",
						},
					},
				},
			},
			want: &ParsedRequest{
				IP:           "5.6.7.8",
				RealIP:       "5.6.7.8",
				ParsedRealIP: netip.MustParseAddr("5.6.7.8"),
				Headers:      nil,
				Cookies:      nil,
				URL:          url.URL{Scheme: "https", Host: "example.com", Path: "/foo/bar"},
				Method:       "GET",
				UserAgent:    "TestAgent",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
			},
		},
		{
			name: "user-agent only in headers, not in nested headers",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "2.2.2.2",
								},
							},
						},
					},
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								":scheme":    "http",
								":authority": "host.com",
								":path":      "/baz",
								":method":    "POST",
								"user-agent": "UA-From-Headers",
							},
							Protocol: "HTTP/2",
							Body:     "",
						},
					},
				},
			},
			want: &ParsedRequest{
				IP:           "2.2.2.2",
				RealIP:       "2.2.2.2",
				ParsedRealIP: netip.MustParseAddr("2.2.2.2"),
				Headers:      nil,
				Cookies:      nil,
				URL:          url.URL{Scheme: "http", Host: "host.com", Path: "/baz"},
				Method:       "POST",
				UserAgent:    "UA-From-Headers",
				Body:         nil,
				ProtoMajor:   2,
				ProtoMinor:   0,
			},
		},
		{
			name: "user-agent only in nested headers",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "3.3.3.3",
								},
							},
						},
					},
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								":scheme":    "http",
								":authority": "nested.com",
								":path":      "/nested",
								":method":    "PUT",
								"foo":        "bar",
							},
							Protocol: "HTTP/2",
							Body:     "abc",
						},
					},
				},
			},
			want: &ParsedRequest{
				IP:           "3.3.3.3",
				RealIP:       "3.3.3.3",
				ParsedRealIP: netip.MustParseAddr("3.3.3.3"),
				Headers:      nil,
				Cookies:      nil,
				URL:          url.URL{Scheme: "http", Host: "nested.com", Path: "/nested"},
				Method:       "PUT",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   2,
				ProtoMinor:   0,
			},
		},
		{
			name: "x-forwarded-for with trusted proxies",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "4.4.4.4",
								},
							},
						},
					},
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								":scheme":         "http",
								":authority":      "xff.com",
								":path":           "/xff",
								":method":         "GET",
								"x-forwarded-for": "10.0.0.1, 8.8.8.8",
							},
							Protocol: "HTTP/1.1",
							Body:     "",
						},
					},
				},
			},
			want: &ParsedRequest{
				IP:           "4.4.4.4",
				RealIP:       "8.8.8.8",
				ParsedRealIP: netip.MustParseAddr("8.8.8.8"),
				Headers:      nil,
				Cookies:      nil,
				URL:          url.URL{Scheme: "http", Host: "xff.com", Path: "/xff"},
				Method:       "GET",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
			},
		},
		{
			name: "x-forwarded-for with mixed-case header key",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "4.4.4.4",
								},
							},
						},
					},
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								":scheme":         "http",
								":authority":      "xff.com",
								":path":           "/xff",
								":method":         "GET",
								"X-Forwarded-For": "10.0.0.1, 8.8.8.8",
							},
							Protocol: "HTTP/1.1",
							Body:     "",
						},
					},
				},
			},
			want: &ParsedRequest{
				IP:           "4.4.4.4",
				RealIP:       "8.8.8.8",
				ParsedRealIP: netip.MustParseAddr("8.8.8.8"),
				Headers:      nil,
				Cookies:      nil,
				URL:          url.URL{Scheme: "http", Host: "xff.com", Path: "/xff"},
				Method:       "GET",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
			},
		},
		{
			name: "x-real-ip with mixed-case header key",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "4.4.4.4",
								},
							},
						},
					},
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								":scheme":    "http",
								":authority": "xff.com",
								":path":      "/xff",
								":method":    "GET",
								"X-Real-IP":  "8.8.8.8",
							},
							Protocol: "HTTP/1.1",
							Body:     "",
						},
					},
				},
			},
			want: &ParsedRequest{
				IP:           "4.4.4.4",
				RealIP:       "8.8.8.8",
				ParsedRealIP: netip.MustParseAddr("8.8.8.8"),
				Headers:      nil,
				Cookies:      nil,
				URL:          url.URL{Scheme: "http", Host: "xff.com", Path: "/xff"},
				Method:       "GET",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.ParseCheckRequest(t.Context(), tt.req)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseCheckRequest_TrustedIPHeader(t *testing.T) {
	r := newTestBouncer(t, config.Config{TrustedIPHeader: "x-envoy-external-address"})
	req := &auth.CheckRequest{
		Attributes: &auth.AttributeContext{
			Source: &auth.AttributeContext_Peer{
				Address: &core.Address{
					Address: &core.Address_SocketAddress{
						SocketAddress: &core.SocketAddress{Address: "1.2.3.4"},
					},
				},
			},
			Request: &auth.AttributeContext_Request{
				Http: &auth.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"X-Envoy-External-Address": "8.8.8.8",
						"x-forwarded-for":          "9.9.9.9",
					},
					Protocol: "HTTP/1.1",
				},
			},
		},
	}

	got := r.ParseCheckRequest(t.Context(), req)
	want := &ParsedRequest{
		IP:           "1.2.3.4",
		RealIP:       "8.8.8.8",
		ParsedRealIP: netip.MustParseAddr("8.8.8.8"),
		Headers:      nil,
		Cookies:      nil,
		URL:          url.URL{},
		Method:       "",
		UserAgent:    "",
		Body:         nil,
		ProtoMajor:   1,
		ProtoMinor:   1,
	}
	assert.Equal(t, want, got)
}

func TestBouncer_Check(t *testing.T) {
	t.Run("bouncer denies", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.MetricsService = newMetricsService(t)

		decisionCache.EXPECT().GetDecision(gomock.Any(), "1.2.3.4").Return(&models.Decision{Type: new("ban")}, nil)

		got := r.Check(t.Context(), mkCheckRequest("1.2.3.4", "http", "example.com", "/foo", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("1.2.3.4", "ban", "crowdsec ban", 403, &models.Decision{Type: new("ban")}, "", &ParsedRequest{
			IP:           "1.2.3.4",
			RealIP:       "1.2.3.4",
			ParsedRealIP: netip.MustParseAddr("1.2.3.4"),
			Headers:      nil,
			Cookies:      nil,
			URL:          url.URL{Scheme: "http", Host: "example.com", Path: "/foo"},
			Method:       "GET",
			UserAgent:    "UT",
			Body:         nil,
			ProtoMajor:   1,
			ProtoMinor:   1,
		}, nil)
		assert.Equal(t, want, got)

		assert.Equal(t, map[string]crowdsec.Metric{
			"CAPI:ban": {Name: "dropped", Unit: "request", Value: 1, Labels: map[string]string{"origin": "CAPI", "remediation": "ban"}},
		}, r.MetricsService.GetSnapshot())
	})

	t.Run("bouncer denies with scenario", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache

		decision := &models.Decision{Type: new("ban"), Scenario: new("crowdsecurity/test"), Origin: new("CAPI"), Duration: new("1h"), Scope: new("Ip"), Value: new("2.2.2.2")}
		decisionCache.EXPECT().GetDecision(gomock.Any(), "2.2.2.2").Return(decision, nil)

		got := r.Check(t.Context(), mkCheckRequest("2.2.2.2", "http", "example.com", "/foo", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("2.2.2.2", "ban", "crowdsecurity/test", 403, decision, "", &ParsedRequest{
			IP:           "2.2.2.2",
			RealIP:       "2.2.2.2",
			ParsedRealIP: netip.MustParseAddr("2.2.2.2"),
			Headers:      nil,
			Cookies:      nil,
			URL:          url.URL{Scheme: "http", Host: "example.com", Path: "/foo"},
			Method:       "GET",
			UserAgent:    "UT",
			Body:         nil,
			ProtoMajor:   1,
			ProtoMinor:   1,
		}, nil)
		assert.Equal(t, want, got)
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.MetricsService = newMetricsService(t)

		decisionCache.EXPECT().GetDecision(gomock.Any(), "3.3.3.3").Return(nil, fmt.Errorf("boom"))

		got := r.Check(t.Context(), mkCheckRequest("3.3.3.3", "http", "example.com", "/foo", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("3.3.3.3", "error", "decision cache error", 500, nil, "", &ParsedRequest{
			IP:           "3.3.3.3",
			RealIP:       "3.3.3.3",
			ParsedRealIP: netip.MustParseAddr("3.3.3.3"),
			Headers:      nil,
			Cookies:      nil,
			URL:          url.URL{Scheme: "http", Host: "example.com", Path: "/foo"},
			Method:       "GET",
			UserAgent:    "UT",
			Body:         nil,
			ProtoMajor:   1,
			ProtoMinor:   1,
		}, nil)
		assert.Equal(t, want, got)

		assert.Empty(t, r.MetricsService.GetSnapshot())
	})

	t.Run("bouncer allows - waf bans", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf
		r.MetricsService = newMetricsService(t)

		decisionCache.EXPECT().GetDecision(gomock.Any(), "4.4.4.4").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "ban"}, nil)

		got := r.Check(t.Context(), mkCheckRequest("4.4.4.4", "https", "host", "/bar", "POST", "HTTP/2", "abc"))
		want := NewCheckedRequest("4.4.4.4", "ban", "ban", 403, nil, "", wantParsed("4.4.4.4", "https", "host", "/bar", "POST", []byte("abc"), 2, 0), nil)
		assert.Equal(t, want, got)

		assert.Equal(t, map[string]crowdsec.Metric{
			"CAPI:ban": {Name: "dropped", Unit: "request", Value: 1, Labels: map[string]string{"origin": "CAPI", "remediation": "ban"}},
		}, r.MetricsService.GetSnapshot())
	})

	t.Run("waf error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf

		decisionCache.EXPECT().GetDecision(gomock.Any(), "6.6.6.6").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{}, fmt.Errorf("waf down"))

		got := r.Check(t.Context(), mkCheckRequest("6.6.6.6", "http", "h", "/p", "GET", "HTTP/1.0", ""))
		want := NewCheckedRequest("6.6.6.6", "error", "error", 500, nil, "", wantParsed("6.6.6.6", "http", "h", "/p", "GET", nil, 1, 0), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf error with failOpen enabled allows request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{WAF: config.WAF{FailOpen: true}})
		r.DecisionCache = decisionCache
		r.WAF = waf

		decisionCache.EXPECT().GetDecision(gomock.Any(), "10.0.0.2").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{}, fmt.Errorf("waf down"))

		got := r.Check(t.Context(), mkCheckRequest("10.0.0.2", "http", "h", "/p", "GET", "HTTP/1.0", ""))
		want := NewCheckedRequest("10.0.0.2", "allow", "waf-unavailable", 200, nil, "", wantParsed("10.0.0.2", "http", "h", "/p", "GET", nil, 1, 0), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf error action with failOpen enabled allows request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{WAF: config.WAF{FailOpen: true}})
		r.DecisionCache = decisionCache
		r.WAF = waf

		decisionCache.EXPECT().GetDecision(gomock.Any(), "10.0.0.4").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "error"}, nil)

		got := r.Check(t.Context(), mkCheckRequest("10.0.0.4", "http", "h", "/p", "GET", "HTTP/1.0", ""))
		want := NewCheckedRequest("10.0.0.4", "allow", "waf-unavailable", 200, nil, "", wantParsed("10.0.0.4", "http", "h", "/p", "GET", nil, 1, 0), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf error with failOpen enabled still enforces LAPI ban", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{WAF: config.WAF{FailOpen: true}})
		r.DecisionCache = decisionCache
		r.WAF = waf

		decision := &models.Decision{Type: new("ban")}
		decisionCache.EXPECT().GetDecision(gomock.Any(), "10.0.0.3").Return(decision, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.Any()).Times(0)

		got := r.Check(t.Context(), mkCheckRequest("10.0.0.3", "http", "h", "/p", "GET", "HTTP/1.0", ""))
		want := NewCheckedRequest("10.0.0.3", "ban", "crowdsec ban", 403, decision, "", wantParsed("10.0.0.3", "http", "h", "/p", "GET", nil, 1, 0), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf action matching is case insensitive", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf

		decisionCache.EXPECT().GetDecision(gomock.Any(), "10.0.0.5").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "ALLOW"}, nil)

		got := r.Check(t.Context(), mkCheckRequest("10.0.0.5", "http", "h", "/p", "GET", "HTTP/1.0", ""))
		want := NewCheckedRequest("10.0.0.5", "allow", "ok", 200, nil, "", wantParsed("10.0.0.5", "http", "h", "/p", "GET", nil, 1, 0), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf returns error action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf

		decisionCache.EXPECT().GetDecision(gomock.Any(), "7.7.7.7").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "error"}, nil)

		got := r.Check(t.Context(), mkCheckRequest("7.7.7.7", "http", "h", "/p", "GET", "HTTP/1.0", ""))
		want := NewCheckedRequest("7.7.7.7", "error", "error", 500, nil, "", wantParsed("7.7.7.7", "http", "h", "/p", "GET", nil, 1, 0), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf returns unknown action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf

		decisionCache.EXPECT().GetDecision(gomock.Any(), "8.8.8.8").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "unknown"}, nil)

		got := r.Check(t.Context(), mkCheckRequest("8.8.8.8", "http", "h", "/p", "GET", "HTTP/1.0", ""))
		want := NewCheckedRequest("8.8.8.8", "unknown", "unknown action", 500, nil, "", wantParsed("8.8.8.8", "http", "h", "/p", "GET", nil, 1, 0), nil)
		assert.Equal(t, want, got)
	})

	t.Run("allow both", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf
		r.MetricsService = newMetricsService(t)

		decisionCache.EXPECT().GetDecision(gomock.Any(), "9.9.9.9").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "allow"}, nil)

		got := r.Check(t.Context(), mkCheckRequest("9.9.9.9", "https", "ex", "/ok", "GET", "HTTP/2", ""))
		want := NewCheckedRequest("9.9.9.9", "allow", "ok", 200, nil, "", wantParsed("9.9.9.9", "https", "ex", "/ok", "GET", nil, 2, 0), nil)
		assert.Equal(t, want, got)

		assert.Equal(t, map[string]crowdsec.Metric{
			"CAPI:bypass": {Name: "processed", Unit: "request", Value: 1, Labels: map[string]string{"origin": "CAPI", "remediation": "bypass"}},
		}, r.MetricsService.GetSnapshot())
	})

	t.Run("waf disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache

		decisionCache.EXPECT().GetDecision(gomock.Any(), "10.0.0.1").Return(nil, nil)

		got := r.Check(t.Context(), mkCheckRequest("10.0.0.1", "https", "ex", "/ok", "GET", "HTTP/2", ""))
		want := NewCheckedRequest("10.0.0.1", "allow", "ok", 200, nil, "", &ParsedRequest{
			IP:           "10.0.0.1",
			RealIP:       "10.0.0.1",
			ParsedRealIP: netip.MustParseAddr("10.0.0.1"),
			Headers:      nil,
			Cookies:      nil,
			URL:          url.URL{Scheme: "https", Host: "ex", Path: "/ok"},
			Method:       "GET",
			UserAgent:    "UT",
			Body:         nil,
			ProtoMajor:   2,
			ProtoMinor:   0,
		}, nil)
		assert.Equal(t, want, got)
	})

	t.Run("exempt list bypasses all checks", func(t *testing.T) {
		r := newTestBouncer(t, config.Config{ExemptIPs: []string{"10.0.0.0/8"}})

		got := r.Check(t.Context(), mkCheckRequest("10.1.2.3", "http", "example.com", "/foo", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("10.1.2.3", "allow", "ip is in exempt list", 200, nil, "", &ParsedRequest{
			IP:           "10.1.2.3",
			RealIP:       "10.1.2.3",
			ParsedRealIP: netip.MustParseAddr("10.1.2.3"),
			Headers:      nil,
			Cookies:      nil,
			URL:          url.URL{Scheme: "http", Host: "example.com", Path: "/foo"},
			Method:       "GET",
			UserAgent:    "UT",
			Body:         nil,
			ProtoMajor:   1,
			ProtoMinor:   1,
		}, nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf captcha - captcha disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		captcha := remediationmocks.NewMockCaptchaService(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf
		r.CaptchaService = captcha

		decisionCache.EXPECT().GetDecision(gomock.Any(), "11.11.11.11").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		captcha.EXPECT().IsEnabled().Return(false)

		got := r.Check(t.Context(), mkCheckRequest("11.11.11.11", "https", "example.com", "/test", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("11.11.11.11", "allow", "captcha disabled", 200, nil, "", wantParsed("11.11.11.11", "https", "example.com", "/test", "GET", nil, 1, 1), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf captcha - captcha nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf

		decisionCache.EXPECT().GetDecision(gomock.Any(), "12.12.12.12").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)

		got := r.Check(t.Context(), mkCheckRequest("12.12.12.12", "https", "example.com", "/test", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("12.12.12.12", "allow", "captcha disabled", 200, nil, "", wantParsed("12.12.12.12", "https", "example.com", "/test", "GET", nil, 1, 1), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf captcha - no challenge needed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		captcha := remediationmocks.NewMockCaptchaService(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf
		r.CaptchaService = captcha

		decisionCache.EXPECT().GetDecision(gomock.Any(), "13.13.13.13").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		captcha.EXPECT().IsEnabled().Return(true)
		captcha.EXPECT().CookieName().Return("session")
		captcha.EXPECT().CreateSession("13.13.13.13", "https://example.com/test", "").Return(nil, nil)

		got := r.Check(t.Context(), mkCheckRequest("13.13.13.13", "https", "example.com", "/test", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("13.13.13.13", "allow", "captcha not required", 200, nil, "", wantParsed("13.13.13.13", "https", "example.com", "/test", "GET", nil, 1, 1), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf captcha - challenge error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		captcha := remediationmocks.NewMockCaptchaService(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf
		r.CaptchaService = captcha

		decisionCache.EXPECT().GetDecision(gomock.Any(), "14.14.14.14").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		captcha.EXPECT().IsEnabled().Return(true)
		captcha.EXPECT().CookieName().Return("session")
		captcha.EXPECT().CreateSession("14.14.14.14", "https://example.com/test", "").Return(nil, fmt.Errorf("session creation failed"))

		got := r.Check(t.Context(), mkCheckRequest("14.14.14.14", "https", "example.com", "/test", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("14.14.14.14", "error", "captcha error", 500, nil, "", wantParsed("14.14.14.14", "https", "example.com", "/test", "GET", nil, 1, 1), nil)
		assert.Equal(t, want, got)
	})

	t.Run("waf captcha - challenge required", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		waf := remediationmocks.NewMockWAF(ctrl)
		captcha := remediationmocks.NewMockCaptchaService(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.WAF = waf
		r.CaptchaService = captcha
		r.MetricsService = newMetricsService(t)

		session := &components.CaptchaSession{ChallengeURL: "https://bouncer.example.com/captcha/challenge?session=abc123"}
		decisionCache.EXPECT().GetDecision(gomock.Any(), "15.15.15.15").Return(nil, nil)
		waf.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		captcha.EXPECT().IsEnabled().Return(true)
		captcha.EXPECT().CookieName().Return("session")
		captcha.EXPECT().CreateSession("15.15.15.15", "https://example.com/test", "").Return(session, nil)

		got := r.Check(t.Context(), mkCheckRequest("15.15.15.15", "https", "example.com", "/test", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("15.15.15.15", "captcha", "captcha required", 302, nil, session.ChallengeURL, wantParsed("15.15.15.15", "https", "example.com", "/test", "GET", nil, 1, 1), session)
		assert.Equal(t, want, got)

		assert.Equal(t, map[string]crowdsec.Metric{
			"CAPI:captcha": {Name: "dropped", Unit: "request", Value: 1, Labels: map[string]string{"origin": "CAPI", "remediation": "captcha"}},
		}, r.MetricsService.GetSnapshot())
	})

	t.Run("bouncer captcha - session token from cookie is passed to CreateSession", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		captcha := remediationmocks.NewMockCaptchaService(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache
		r.CaptchaService = captcha

		session := &components.CaptchaSession{ChallengeURL: "https://bouncer.example.com/captcha/challenge?session=abc123"}
		decisionCache.EXPECT().GetDecision(gomock.Any(), "16.16.16.16").Return(&models.Decision{Type: new("captcha")}, nil)
		captcha.EXPECT().IsEnabled().Return(true)
		captcha.EXPECT().CookieName().Return("session")
		captcha.EXPECT().CreateSession("16.16.16.16", "https://example.com/test", "abc123").Return(session, nil)

		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{Address: "16.16.16.16"}},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":scheme":    "https",
							":authority": "example.com",
							":path":      "/test",
							":method":    "GET",
							"cookie":     "session=abc123; theme=dark",
						},
						Protocol: "HTTP/1.1",
					},
				},
			},
		}

		got := r.Check(t.Context(), req)
		want := NewCheckedRequest("16.16.16.16", "captcha", "captcha required", 302, &models.Decision{Type: new("captcha")}, session.ChallengeURL, &ParsedRequest{
			IP:           "16.16.16.16",
			RealIP:       "16.16.16.16",
			ParsedRealIP: netip.MustParseAddr("16.16.16.16"),
			Headers:      nil,
			Cookies:      map[string]string{"session": "abc123", "theme": "dark"},
			URL:          url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
			Method:       "GET",
			UserAgent:    "",
			Body:         nil,
			ProtoMajor:   1,
			ProtoMinor:   1,
		}, session)
		assert.Equal(t, want, got)
	})

	t.Run("bouncer captcha decision - captcha service disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		r := newTestBouncer(t, config.Config{})
		r.DecisionCache = decisionCache

		decisionCache.EXPECT().GetDecision(gomock.Any(), "17.17.17.17").Return(&models.Decision{Type: new("captcha")}, nil)

		got := r.Check(t.Context(), mkCheckRequest("17.17.17.17", "https", "example.com", "/test", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("17.17.17.17", "allow", "captcha disabled", 200, nil, "", &ParsedRequest{
			IP:           "17.17.17.17",
			RealIP:       "17.17.17.17",
			ParsedRealIP: netip.MustParseAddr("17.17.17.17"),
			Headers:      nil,
			Cookies:      nil,
			URL:          url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
			Method:       "GET",
			UserAgent:    "UT",
			Body:         nil,
			ProtoMajor:   1,
			ProtoMinor:   1,
		}, nil)
		assert.Equal(t, want, got)
	})

	t.Run("bouncer disabled - waf disabled - captcha disabled", func(t *testing.T) {
		r := newTestBouncer(t, config.Config{})

		got := r.Check(t.Context(), mkCheckRequest("18.18.18.18", "https", "example.com", "/test", "GET", "HTTP/1.1", ""))
		want := NewCheckedRequest("18.18.18.18", "allow", "ok", 200, nil, "", &ParsedRequest{
			IP:           "18.18.18.18",
			RealIP:       "18.18.18.18",
			ParsedRealIP: netip.MustParseAddr("18.18.18.18"),
			Headers:      nil,
			Cookies:      nil,
			URL:          url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
			Method:       "GET",
			UserAgent:    "UT",
			Body:         nil,
			ProtoMajor:   1,
			ProtoMinor:   1,
		}, nil)
		assert.Equal(t, want, got)
	})
}

func Test_parseCookies(t *testing.T) {
	tests := []struct {
		name         string
		cookieHeader string
		want         map[string]string
	}{
		{
			name:         "empty string returns empty map",
			cookieHeader: "",
			want:         nil,
		},
		{
			name:         "single cookie",
			cookieHeader: "session_id=abc123",
			want: map[string]string{
				"session_id": "abc123",
			},
		},
		{
			name:         "multiple cookies",
			cookieHeader: "session_id=abc123; user_id=42; theme=dark",
			want: map[string]string{
				"session_id": "abc123",
				"user_id":    "42",
				"theme":      "dark",
			},
		},
		{
			name:         "cookies with spaces",
			cookieHeader: "session_id=abc123 ; user_id=42 ;theme=dark",
			want: map[string]string{
				"session_id": "abc123",
				"user_id":    "42",
				"theme":      "dark",
			},
		},
		{
			name:         "cookie with URL-encoded value stays encoded",
			cookieHeader: "redirect_url=https%3A%2F%2Fexample.com%2Fpath",
			want: map[string]string{
				"redirect_url": "https%3A%2F%2Fexample.com%2Fpath",
			},
		},
		{
			name:         "cookie with equals in value",
			cookieHeader: "data=key=value",
			want: map[string]string{
				"data": "key=value",
			},
		},
		{
			name:         "cookie with special characters",
			cookieHeader: "token=abc-123_456.789",
			want: map[string]string{
				"token": "abc-123_456.789",
			},
		},
		{
			name:         "captcha_verified cookie",
			cookieHeader: "captcha_verified=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpcCI6IjEyNy4wLjAuMSJ9.abc123",
			want: map[string]string{
				"captcha_verified": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpcCI6IjEyNy4wLjAuMSJ9.abc123",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCookies(tt.cookieHeader)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBouncer_IsReady(t *testing.T) {
	t.Run("returns true when bouncer is disabled", func(t *testing.T) {
		r := newTestBouncer(t, config.Config{})
		assert.True(t, r.IsReady())
	})

	t.Run("returns false when bouncer enabled but cache is nil", func(t *testing.T) {
		r := newTestBouncer(t, config.Config{
			Bouncer: config.Bouncer{Enabled: true, LAPIURL: "http://localhost:8080", ApiKey: "test"},
		})
		r.DecisionCache = nil
		assert.False(t, r.IsReady())
	})

	t.Run("returns false when cache not synced", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		decisionCache.EXPECT().IsReady().Return(false)
		r := newTestBouncer(t, config.Config{
			Bouncer: config.Bouncer{Enabled: true, LAPIURL: "http://localhost:8080", ApiKey: "test"},
		})
		r.DecisionCache = decisionCache
		assert.False(t, r.IsReady())
	})

	t.Run("returns true when cache synced", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
		decisionCache.EXPECT().IsReady().Return(true)
		r := newTestBouncer(t, config.Config{
			Bouncer: config.Bouncer{Enabled: true, LAPIURL: "http://localhost:8080", ApiKey: "test"},
		})
		r.DecisionCache = decisionCache
		assert.True(t, r.IsReady())
	})
}

func TestBouncer_Check_ContextCancelled(t *testing.T) {
	ctrl := gomock.NewController(t)
	decisionCache := remediationmocks.NewMockDecisionCache(ctrl)
	decisionCache.EXPECT().GetDecision(gomock.Any(), gomock.Any()).Return(nil, context.Canceled)
	decisionCache.EXPECT().IsReady().Return(true).AnyTimes()

	r, err := New(config.Config{}, recorder.NewNoOp(), nil)
	require.NoError(t, err)
	r.DecisionCache = decisionCache

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	req := mkCheckRequest("1.2.3.4", "https", "example.com", "/path", "GET", "HTTP/1.1", "")
	result := r.Check(ctx, req)

	assert.Equal(t, "error", result.Action)
}
