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
			name:         "trustedIPHeader unset (default), x-envoy-external-address header ignored, x-forwarded-for used as before",
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
			if got != tt.want {
				t.Errorf("ExtractRealIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractRealIPFromHTTP(t *testing.T) {
	trusted := []netip.Prefix{
		parseCIDROrFail(t, "10.0.0.0/8"),
		parseCIDROrFail(t, "192.168.0.0/16"),
	}

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
		trustedProxies  []netip.Prefix
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
			trustedProxies: trusted,
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
			trustedProxies: trusted,
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
			b := &Bouncer{
				TrustedProxies:  tt.trustedProxies,
				TrustedIPHeader: tt.trustedIPHeader,
			}
			got := b.ExtractRealIPFromHTTP(newReq(tt.remoteAddr, tt.headers))
			if got != tt.want {
				t.Errorf("ExtractRealIPFromHTTP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsExemptIP(t *testing.T) {
	exemptIPs := []netip.Prefix{
		parseCIDROrFail(t, "10.0.0.0/8"),
		parseCIDROrFail(t, "192.168.0.0/16"),
		parseCIDROrFail(t, "2001:db8::/32"),
	}

	tests := []struct {
		name      string
		ip        netip.Addr
		exemptIPs []netip.Prefix
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
			exemptIPs: exemptIPs,
			want:      true,
		},
		{
			name:      "IP not in exempt IPs (IPv4)",
			ip:        netip.MustParseAddr("8.8.8.8"),
			exemptIPs: exemptIPs,
			want:      false,
		},
		{
			name:      "IP in exempt IPs (second range)",
			ip:        netip.MustParseAddr("192.168.1.100"),
			exemptIPs: exemptIPs,
			want:      true,
		},
		{
			name:      "Invalid IP returns false",
			ip:        netip.Addr{},
			exemptIPs: exemptIPs,
			want:      false,
		},
		{
			name:      "IPv6 in exempt IPs",
			ip:        netip.MustParseAddr("2001:db8::1"),
			exemptIPs: exemptIPs,
			want:      true,
		},
		{
			name:      "IPv6 not in exempt IPs",
			ip:        netip.MustParseAddr("2001:dead:beef::1"),
			exemptIPs: exemptIPs,
			want:      false,
		},
		{
			name:      "IPv4-mapped IPv6 in exempt IPs",
			ip:        netip.MustParseAddr("::ffff:10.1.2.3"),
			exemptIPs: exemptIPs,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Bouncer{ExemptIPs: tt.exemptIPs}
			got := b.isExemptIP(tt.ip)
			if got != tt.want {
				t.Errorf("isExemptIP(%v) = %v, want %v", tt.ip, got, tt.want)
			}
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
			if got != tt.want {
				t.Errorf("isTrustedProxy(%q, ...) = %v, want %v", tt.ip, got, tt.want)
			}
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
			if got != tt.want {
				t.Errorf("isTrustedProxyAddr(%v, ...) = %v, want %v", tt.addr, got, tt.want)
			}
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
		{
			name:     "Invalid CIDR returns error",
			input:    []string{"10.0.0.0/99"},
			wantCIDR: nil,
			wantErr:  true,
		},
		{
			name:     "Multiple, one invalid",
			input:    []string{"10.0.0.1", "bad-cidr"},
			wantCIDR: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPNets(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(got) != len(tt.wantCIDR) {
				t.Errorf("got %d CIDRs, want %d", len(got), len(tt.wantCIDR))
				return
			}
			for i, want := range tt.wantCIDR {
				if got[i].String() != want {
					t.Errorf("got[%d]=%q, want %q", i, got[i].String(), want)
				}
			}
		})
	}
}

func TestParseCheckRequest(t *testing.T) {
	trusted := []netip.Prefix{
		parseCIDROrFail(t, "10.0.0.0/8"),
	}
	r := &Bouncer{TrustedProxies: trusted}

	tests := []struct {
		name string
		req  *auth.CheckRequest
		want *ParsedRequest
	}{
		{
			name: "nil request returns empty ParsedRequest",
			req:  nil,
			want: &ParsedRequest{},
		},
		{
			name: "nil attributes returns empty ParsedRequest",
			req:  &auth.CheckRequest{},
			want: &ParsedRequest{},
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
			got := r.ParseCheckRequest(context.Background(), tt.req)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseCheckRequest_TrustedIPHeader(t *testing.T) {
	r := &Bouncer{TrustedIPHeader: "x-envoy-external-address"}
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

	got := r.ParseCheckRequest(context.Background(), req)
	want := &ParsedRequest{
		IP:           "1.2.3.4",
		RealIP:       "8.8.8.8",
		ParsedRealIP: netip.MustParseAddr("8.8.8.8"),
		ProtoMajor:   1,
		ProtoMinor:   1,
	}
	assert.Equal(t, want, got)
}

func TestBouncer_Check(t *testing.T) {
	mkReq := func(ip, scheme, authority, path, method, proto, body string) *auth.CheckRequest {
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

	t.Run("bouncer denies", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				Bouncer: config.Bouncer{
					BanStatusCode: 403,
				},
			},
		}

		req := mkReq("1.2.3.4", "http", "example.com", "/foo", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "1.2.3.4").Return(&models.Decision{Type: new("ban")}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:          "1.2.3.4",
			Action:      "ban",
			Reason:      "crowdsec ban",
			HTTPStatus:  403,
			RedirectURL: "",
			Decision:    &models.Decision{Type: new("ban")},
			ParsedRequest: &ParsedRequest{
				IP:           "1.2.3.4",
				RealIP:       "1.2.3.4",
				ParsedRealIP: netip.MustParseAddr("1.2.3.4"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/foo", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "example.com", Path: "/foo"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
			CaptchaSession: nil,
		}
		require.Equal(t, want, got)

		actualMetrics := r.MetricsService.GetSnapshot()
		wantMetric := crowdsec.Metric{
			Name:  "dropped",
			Unit:  "request",
			Value: 1,
			Labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "ban",
			},
		}
		metric, ok := actualMetrics["CAPI:ban"]
		require.True(t, ok, "expected CAPI:ban metric to exist")
		assert.Equal(t, wantMetric, metric)
	})

	t.Run("bouncer denies with scenario", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				Bouncer: config.Bouncer{
					BanStatusCode: 403,
				},
			},
		}

		req := mkReq("2.2.2.2", "http", "example.com", "/foo", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "2.2.2.2").Return(&models.Decision{Type: new("ban"), Scenario: new("crowdsecurity/test"), Origin: new("CAPI"), Duration: new("1h"), Scope: new("Ip"), Value: new("2.2.2.2")}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:          "2.2.2.2",
			Action:      "ban",
			Reason:      "crowdsecurity/test",
			HTTPStatus:  403,
			RedirectURL: "",
			Decision:    &models.Decision{Type: new("ban"), Scenario: new("crowdsecurity/test"), Origin: new("CAPI"), Duration: new("1h"), Scope: new("Ip"), Value: new("2.2.2.2")},
			ParsedRequest: &ParsedRequest{
				IP:           "2.2.2.2",
				RealIP:       "2.2.2.2",
				ParsedRealIP: netip.MustParseAddr("2.2.2.2"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/foo", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "example.com", Path: "/foo"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
			CaptchaSession: nil,
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("5.6.7.8", "http", "example.com", "/foo", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "5.6.7.8").Return(nil, fmt.Errorf("boom"))

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:          "5.6.7.8",
			Action:      "error",
			Reason:      "decision cache error",
			HTTPStatus:  500,
			RedirectURL: "",
			Decision:    nil,
			ParsedRequest: &ParsedRequest{
				IP:           "5.6.7.8",
				RealIP:       "5.6.7.8",
				ParsedRealIP: netip.MustParseAddr("5.6.7.8"),
				URL:          url.URL{Scheme: "http", Host: "example.com", Path: "/foo"},
				Method:       "GET",
				UserAgent:    "UT",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
				Headers: map[string]string{
					":scheme":    "http",
					":authority": "example.com",
					":path":      "/foo",
					":method":    "GET",
					"user-agent": "UT",
				},
			},
			CaptchaSession: nil,
		}
		require.Equal(t, want, got)

		actualMetrics := r.MetricsService.GetSnapshot()
		_, ok := actualMetrics["CAPI:ban"]
		assert.False(t, ok, "expected no CAPI:ban metric on error")
	})

	t.Run("waf denies after bouncer allows", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				Bouncer: config.Bouncer{
					BanStatusCode: 403,
				},
			},
		}

		req := mkReq("9.9.9.9", "https", "host", "/bar", "POST", "HTTP/2", "abc")

		mb.EXPECT().GetDecision(gomock.Any(), "9.9.9.9").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "ban"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:          "9.9.9.9",
			Action:      "ban",
			Reason:      "ban",
			HTTPStatus:  403,
			RedirectURL: "",
			ParsedRequest: &ParsedRequest{
				IP:           "9.9.9.9",
				RealIP:       "9.9.9.9",
				ParsedRealIP: netip.MustParseAddr("9.9.9.9"),
				Headers:      map[string]string{":authority": "host", ":method": "POST", ":path": "/bar", ":scheme": "https", "user-agent": "UT"},

				URL:        url.URL{Scheme: "https", Host: "host", Path: "/bar"},
				Method:     "POST",
				UserAgent:  "UT",
				Body:       []byte("abc"),
				ProtoMajor: 2,
				ProtoMinor: 0,
			},
			CaptchaSession: nil,
		}
		require.Equal(t, want, got)

		actualMetrics := r.MetricsService.GetSnapshot()
		wantMetric := crowdsec.Metric{
			Name:  "dropped",
			Unit:  "request",
			Value: 1,
			Labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "ban",
			},
		}
		metric, ok := actualMetrics["CAPI:ban"]
		require.True(t, ok, "expected CAPI:ban metric to exist")
		assert.Equal(t, wantMetric, metric)
	})

	t.Run("waf error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("10.0.0.1", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "10.0.0.1").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{}, fmt.Errorf("waf down"))

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "10.0.0.1",
			Action:     "error",
			Reason:     "error",
			HTTPStatus: 500,
			ParsedRequest: &ParsedRequest{
				IP:           "10.0.0.1",
				RealIP:       "10.0.0.1",
				ParsedRealIP: netip.MustParseAddr("10.0.0.1"),
				Headers:      map[string]string{":authority": "h", ":method": "GET", ":path": "/p", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "h", Path: "/p"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 0,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("waf error with failOpen enabled allows request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				WAF: config.WAF{
					FailOpen: true,
				},
			},
		}

		req := mkReq("10.0.0.2", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "10.0.0.2").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{}, fmt.Errorf("waf down"))

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "10.0.0.2",
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "10.0.0.2",
				RealIP:       "10.0.0.2",
				ParsedRealIP: netip.MustParseAddr("10.0.0.2"),
				Headers:      map[string]string{":authority": "h", ":method": "GET", ":path": "/p", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "h", Path: "/p"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 0,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("waf error action with failOpen enabled allows request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				WAF: config.WAF{
					FailOpen: true,
				},
			},
		}

		req := mkReq("10.0.0.4", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "10.0.0.4").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "error"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "10.0.0.4",
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "10.0.0.4",
				RealIP:       "10.0.0.4",
				ParsedRealIP: netip.MustParseAddr("10.0.0.4"),
				Headers:      map[string]string{":authority": "h", ":method": "GET", ":path": "/p", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "h", Path: "/p"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 0,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("waf error with failOpen enabled still enforces LAPI ban", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				Bouncer: config.Bouncer{
					BanStatusCode: 403,
				},
				WAF: config.WAF{
					FailOpen: true,
				},
			},
		}

		req := mkReq("10.0.0.3", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "10.0.0.3").Return(&models.Decision{Type: new("ban")}, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.Any()).Times(0)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:          "10.0.0.3",
			Action:      "ban",
			Reason:      "crowdsec ban",
			HTTPStatus:  403,
			Decision:    &models.Decision{Type: new("ban")},
			RedirectURL: "",
			ParsedRequest: &ParsedRequest{
				IP:           "10.0.0.3",
				RealIP:       "10.0.0.3",
				ParsedRealIP: netip.MustParseAddr("10.0.0.3"),
				Headers:      map[string]string{":authority": "h", ":method": "GET", ":path": "/p", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "h", Path: "/p"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 0,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("allow both", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("7.7.7.7", "https", "ex", "/ok", "GET", "HTTP/2", "")

		mb.EXPECT().GetDecision(gomock.Any(), "7.7.7.7").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "allow"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "7.7.7.7",
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "7.7.7.7",
				RealIP:       "7.7.7.7",
				ParsedRealIP: netip.MustParseAddr("7.7.7.7"),
				Headers:      map[string]string{":authority": "ex", ":method": "GET", ":path": "/ok", ":scheme": "https", "user-agent": "UT"},

				URL:        url.URL{Scheme: "https", Host: "ex", Path: "/ok"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 2,
				ProtoMinor: 0,
			},
		}
		require.Equal(t, want, got)

		actualMetrics := r.MetricsService.GetSnapshot()
		wantMetric := crowdsec.Metric{
			Name:  "processed",
			Unit:  "request",
			Value: 1,
			Labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "bypass",
			},
		}
		metric, ok := actualMetrics["CAPI:bypass"]
		require.True(t, ok, "expected CAPI:bypass metric to exist")
		assert.Equal(t, wantMetric, metric)
	})

	t.Run("waf denies with ban action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("8.8.8.8", "https", "host", "/bar", "POST", "HTTP/2", "abc")

		mb.EXPECT().GetDecision(gomock.Any(), "8.8.8.8").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "ban"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "8.8.8.8",
			Action:     "ban",
			Reason:     "ban",
			HTTPStatus: 403,
			ParsedRequest: &ParsedRequest{
				IP:           "8.8.8.8",
				RealIP:       "8.8.8.8",
				ParsedRealIP: netip.MustParseAddr("8.8.8.8"),
				Headers:      map[string]string{":authority": "host", ":method": "POST", ":path": "/bar", ":scheme": "https", "user-agent": "UT"},

				URL:        url.URL{Scheme: "https", Host: "host", Path: "/bar"},
				Method:     "POST",
				UserAgent:  "UT",
				Body:       []byte("abc"),
				ProtoMajor: 2,
				ProtoMinor: 0,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("waf returns error action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("11.11.11.11", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "11.11.11.11").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "error"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "11.11.11.11",
			Action:     "error",
			Reason:     "error",
			HTTPStatus: 500,
			ParsedRequest: &ParsedRequest{
				IP:           "11.11.11.11",
				RealIP:       "11.11.11.11",
				ParsedRealIP: netip.MustParseAddr("11.11.11.11"),
				Headers:      map[string]string{":authority": "h", ":method": "GET", ":path": "/p", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "h", Path: "/p"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 0,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("waf returns unknown action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("12.12.12.12", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "12.12.12.12").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "unknown"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "12.12.12.12",
			Action:     "unknown",
			Reason:     "unknown action",
			HTTPStatus: 500,
			ParsedRequest: &ParsedRequest{
				IP:           "12.12.12.12",
				RealIP:       "12.12.12.12",
				ParsedRealIP: netip.MustParseAddr("12.12.12.12"),
				Headers:      map[string]string{":authority": "h", ":method": "GET", ":path": "/p", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "h", Path: "/p"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 0,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("waf disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: nil, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("13.13.13.13", "https", "ex", "/ok", "GET", "HTTP/2", "")

		mb.EXPECT().GetDecision(gomock.Any(), "13.13.13.13").Return(nil, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "13.13.13.13",
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "13.13.13.13",
				RealIP:       "13.13.13.13",
				ParsedRealIP: netip.MustParseAddr("13.13.13.13"),
				URL:          url.URL{Scheme: "https", Host: "ex", Path: "/ok"},
				Method:       "GET",
				UserAgent:    "UT",
				Body:         nil,
				ProtoMajor:   2,
				ProtoMinor:   0,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("exempt list bypasses all checks", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		exemptIPs := []netip.Prefix{
			parseCIDROrFail(t, "10.0.0.0/8"),
		}

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			CaptchaService:     mc,
			ExemptIPs:          exemptIPs,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
		}

		req := mkReq("10.0.0.1", "http", "example.com", "/foo", "GET", "HTTP/1.1", "")

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "10.0.0.1",
			Action:     "allow",
			Reason:     "ip is in exempt list",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "10.0.0.1",
				RealIP:       "10.0.0.1",
				ParsedRealIP: netip.MustParseAddr("10.0.0.1"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/foo", ":scheme": "http", "user-agent": "UT"},

				URL:        url.URL{Scheme: "http", Host: "example.com", Path: "/foo"},
				Method:     "GET",
				UserAgent:  "UT",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		}
		require.Equal(t, want, got)
	})
}

func TestBouncer_Check_AllScenarios(t *testing.T) {
	mkReq := func(ip, scheme, authority, path, method, proto, body string) *auth.CheckRequest {
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
						},
						Protocol: proto,
						Body:     body,
					},
				},
			},
		}
	}

	t.Run("bouncer disabled - waf disabled - captcha disabled", func(t *testing.T) {
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r, err := New(config.Config{}, rec, nil)
		require.NoError(t, err)
		r.MetricsService = collector
		req := mkReq("1.1.1.1", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "1.1.1.1",
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "1.1.1.1",
				RealIP:       "1.1.1.1",
				ParsedRealIP: netip.MustParseAddr("1.1.1.1"),
				URL:          url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:       "GET",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
			},
		}
		require.Equal(t, want, got)

		actualMetrics := r.MetricsService.GetSnapshot()
		wantMetric := crowdsec.Metric{
			Name:  "processed",
			Unit:  "request",
			Value: 1,
			Labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "bypass",
			},
		}
		metric, ok := actualMetrics["CAPI:bypass"]
		require.True(t, ok, "expected CAPI:bypass metric to exist")
		assert.Equal(t, wantMetric, metric)
	})

	t.Run("bouncer denies - short circuit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("2.2.2.2", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "2.2.2.2").Return(&models.Decision{Type: new("ban")}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "2.2.2.2",
			Action:     "ban",
			Reason:     "crowdsec ban",
			HTTPStatus: 403,
			Decision:   &models.Decision{Type: new("ban")},
			ParsedRequest: &ParsedRequest{
				IP:           "2.2.2.2",
				RealIP:       "2.2.2.2",
				ParsedRealIP: netip.MustParseAddr("2.2.2.2"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/test", ":scheme": "https"},

				URL:        url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:     "GET",
				UserAgent:  "",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer error - short circuit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			CaptchaService:     mc,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				Bouncer: config.Bouncer{
					BanStatusCode: 403,
				},
			},
		}

		req := mkReq("3.3.3.3", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "3.3.3.3").Return(nil, fmt.Errorf("bouncer failed"))

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:          "3.3.3.3",
			Action:      "error",
			Reason:      "decision cache error",
			HTTPStatus:  500,
			RedirectURL: "",
			Decision:    nil,
			ParsedRequest: &ParsedRequest{
				IP:           "3.3.3.3",
				RealIP:       "3.3.3.3",
				ParsedRealIP: netip.MustParseAddr("3.3.3.3"),
				URL:          url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:       "GET",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
				Headers: map[string]string{
					":scheme":    "https",
					":authority": "example.com",
					":path":      "/test",
					":method":    "GET",
				},
			},
			CaptchaSession: nil,
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer allows - waf bans", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("4.4.4.4", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "4.4.4.4").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "ban"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "4.4.4.4",
			Action:     "ban",
			Reason:     "ban",
			HTTPStatus: 403,
			ParsedRequest: &ParsedRequest{
				IP:           "4.4.4.4",
				RealIP:       "4.4.4.4",
				ParsedRealIP: netip.MustParseAddr("4.4.4.4"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/test", ":scheme": "https"},

				URL:        url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:     "GET",
				UserAgent:  "",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer allows - waf bans", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("5.5.5.5", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "5.5.5.5").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "ban"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "5.5.5.5",
			Action:     "ban",
			Reason:     "ban",
			HTTPStatus: 403,
			ParsedRequest: &ParsedRequest{
				IP:           "5.5.5.5",
				RealIP:       "5.5.5.5",
				ParsedRealIP: netip.MustParseAddr("5.5.5.5"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/test", ":scheme": "https"},

				URL:        url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:     "GET",
				UserAgent:  "",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer allows - waf errors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("6.6.6.6", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "6.6.6.6").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{}, fmt.Errorf("waf connection failed"))

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "6.6.6.6",
			Action:     "error",
			Reason:     "error",
			HTTPStatus: 500,
			ParsedRequest: &ParsedRequest{
				IP:           "6.6.6.6",
				RealIP:       "6.6.6.6",
				ParsedRealIP: netip.MustParseAddr("6.6.6.6"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/test", ":scheme": "https"},

				URL:        url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:     "GET",
				UserAgent:  "",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer allows - waf errors - fail open", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			CaptchaService:     mc,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				WAF: config.WAF{
					FailOpen: true,
				},
			},
		}

		req := mkReq("6.6.6.7", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "6.6.6.7").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{}, fmt.Errorf("waf connection failed"))

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "6.6.6.7",
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "6.6.6.7",
				RealIP:       "6.6.6.7",
				ParsedRealIP: netip.MustParseAddr("6.6.6.7"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/test", ":scheme": "https"},

				URL:        url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:     "GET",
				UserAgent:  "",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer allows - waf returns error action - fail open", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{
			DecisionCache:      mb,
			WAF:                mw,
			CaptchaService:     mc,
			MetricsService:     collector,
			PrometheusRecorder: rec,
			remediationMetrics: newRemediationMetrics(),
			config: config.Config{
				WAF: config.WAF{
					FailOpen: true,
				},
			},
		}

		req := mkReq("7.7.7.8", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "7.7.7.8").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "error"}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "7.7.7.8",
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "7.7.7.8",
				RealIP:       "7.7.7.8",
				ParsedRealIP: netip.MustParseAddr("7.7.7.8"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/test", ":scheme": "https"},

				URL:        url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:     "GET",
				UserAgent:  "",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer fails closed - waf returns error action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("7.7.7.7", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "7.7.7.7").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "error"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "error" || got.Reason != "error" || got.HTTPStatus != 500 || got.IP != "7.7.7.7" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf unknown action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("8.8.8.8", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "8.8.8.8").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "mystery"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "mystery" || got.Reason != "unknown action" || got.HTTPStatus != 500 || got.IP != "8.8.8.8" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf allows - full allow", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}
		req := mkReq("9.9.9.9", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "9.9.9.9").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "allow"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "allow" || got.Reason != "ok" || got.HTTPStatus != 200 || got.IP != "9.9.9.9" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf captcha - captcha disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

		req := mkReq("10.10.10.10", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "10.10.10.10").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(false)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "10.10.10.10",
			Action:     "allow",
			Reason:     "captcha disabled",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "10.10.10.10",
				RealIP:       "10.10.10.10",
				ParsedRealIP: netip.MustParseAddr("10.10.10.10"),
				Headers:      map[string]string{":authority": "example.com", ":method": "GET", ":path": "/test", ":scheme": "https"},

				URL:        url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:     "GET",
				UserAgent:  "",
				Body:       nil,
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		}
		require.Equal(t, want, got)
	})

	t.Run("bouncer allows - waf captcha - captcha nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: nil, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}
		req := mkReq("11.11.11.11", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "11.11.11.11").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "allow" || got.Reason != "captcha disabled" || got.HTTPStatus != 200 || got.IP != "11.11.11.11" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf captcha - captcha enabled - no challenge needed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}
		req := mkReq("12.12.12.12", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "12.12.12.12").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().CookieName().Return("session")
		mc.EXPECT().CreateSession("12.12.12.12", "https://example.com/test", "").Return(nil, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "allow" || got.Reason != "captcha not required" || got.HTTPStatus != 200 || got.IP != "12.12.12.12" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf captcha - captcha enabled - challenge error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}
		req := mkReq("13.13.13.13", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "13.13.13.13").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().CookieName().Return("session")
		mc.EXPECT().CreateSession("13.13.13.13", "https://example.com/test", "").Return(nil, fmt.Errorf("session creation failed"))

		got := r.Check(context.Background(), req)
		if got.Action != "error" || got.Reason != "captcha error" || got.HTTPStatus != 500 || got.IP != "13.13.13.13" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf captcha - captcha enabled - challenge required", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}
		req := mkReq("14.14.14.14", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "14.14.14.14").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().CookieName().Return("session")
		mc.EXPECT().CreateSession("14.14.14.14", "https://example.com/test", "").Return(&components.CaptchaSession{
			ChallengeURL: "https://bouncer.example.com/captcha/challenge?session=abc123",
		}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "captcha" || got.Reason != "captcha required" || got.HTTPStatus != 302 || got.IP != "14.14.14.14" || got.RedirectURL != "https://bouncer.example.com/captcha/challenge?session=abc123" {
			t.Fatalf("unexpected result: %+v", got)
		}

		actualMetrics := r.MetricsService.GetSnapshot()
		wantMetric := crowdsec.Metric{
			Name:  "dropped",
			Unit:  "request",
			Value: 1,
			Labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "captcha",
			},
		}
		metric, ok := actualMetrics["CAPI:captcha"]
		require.True(t, ok, "expected CAPI:captcha metric to exist")
		assert.Equal(t, wantMetric, metric)
	})

	t.Run("bouncer captcha - session token from cookie is passed to CreateSession", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}

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

		mb.EXPECT().GetDecision(gomock.Any(), "16.16.16.16").Return(&models.Decision{Type: new("captcha")}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().CookieName().Return("session")
		mc.EXPECT().CreateSession("16.16.16.16", "https://example.com/test", "abc123").Return(&components.CaptchaSession{
			ChallengeURL: "https://bouncer.example.com/captcha/challenge?session=abc123",
		}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "captcha" || got.HTTPStatus != 302 || got.RedirectURL != "https://bouncer.example.com/captcha/challenge?session=abc123" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer captcha - direct to captcha flow", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}
		req := mkReq("15.15.15.15", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "15.15.15.15").Return(&models.Decision{Type: new("captcha")}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().CookieName().Return("session")
		mc.EXPECT().CreateSession("15.15.15.15", "https://example.com/test", "").Return(&components.CaptchaSession{
			ChallengeURL: "https://bouncer.example.com/captcha/challenge?session=crowdsec123",
		}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:          "15.15.15.15",
			Action:      "captcha",
			Reason:      "captcha required",
			HTTPStatus:  302,
			RedirectURL: "https://bouncer.example.com/captcha/challenge?session=crowdsec123",
			Decision:    &models.Decision{Type: new("captcha")},
			ParsedRequest: &ParsedRequest{
				IP:           "15.15.15.15",
				RealIP:       "15.15.15.15",
				ParsedRealIP: netip.MustParseAddr("15.15.15.15"),
				URL:          url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:       "GET",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
				Headers: map[string]string{
					":scheme":    "https",
					":authority": "example.com",
					":path":      "/test",
					":method":    "GET",
				},
			},
			CaptchaSession: &components.CaptchaSession{
				ChallengeURL: "https://bouncer.example.com/captcha/challenge?session=crowdsec123",
			},
		}
		require.Equal(t, want, got)

		actualMetrics := r.MetricsService.GetSnapshot()
		wantMetric := crowdsec.Metric{
			Name:  "dropped",
			Unit:  "request",
			Value: 1,
			Labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "captcha",
			},
		}
		metric, ok := actualMetrics["CAPI:captcha"]
		require.True(t, ok, "expected CAPI:captcha metric to exist")
		assert.Equal(t, wantMetric, metric)
	})

	t.Run("bouncer returns captcha decision - captcha service disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r, err := New(config.Config{}, rec, nil)
		require.NoError(t, err)
		r.DecisionCache = mb
		r.MetricsService = collector
		req := mkReq("16.16.16.16", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "16.16.16.16").Return(&models.Decision{Type: new("captcha")}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:         "16.16.16.16",
			Action:     "allow",
			Reason:     "captcha disabled",
			HTTPStatus: 200,
			ParsedRequest: &ParsedRequest{
				IP:           "16.16.16.16",
				RealIP:       "16.16.16.16",
				ParsedRealIP: netip.MustParseAddr("16.16.16.16"),
				URL:          url.URL{Scheme: "https", Host: "example.com", Path: "/test"},
				Method:       "GET",
				UserAgent:    "",
				Body:         nil,
				ProtoMajor:   1,
				ProtoMinor:   1,
				Headers:      nil,
				Cookies:      nil,
			},
		}
		require.Equal(t, want, got)
	})
}

func TestBouncer_CaptchaRedirectURL(t *testing.T) {
	mkReq := func(ip, scheme, authority, path, method, proto, body string) *auth.CheckRequest {
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
						},
						Protocol: proto,
						Body:     body,
					},
				},
			},
		}
	}

	t.Run("captcha redirect with callbackURL", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "test-bouncer",
			Version:     "v1.0.0",
		})
		require.NoError(t, err)

		rec := recorder.NewNoOp()
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, MetricsService: collector, PrometheusRecorder: rec, remediationMetrics: newRemediationMetrics()}
		req := mkReq("1.2.3.4", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "1.2.3.4").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().CookieName().Return("session")
		mc.EXPECT().CreateSession("1.2.3.4", "https://example.com/test", "").Return(&components.CaptchaSession{
			ChallengeURL: "https://bouncer.example.com/captcha/challenge?session=session123",
		}, nil)

		got := r.Check(context.Background(), req)

		if got.Action != "captcha" {
			t.Fatalf("expected captcha action, got %s", got.Action)
		}
		if got.HTTPStatus != 302 {
			t.Fatalf("expected 302 status, got %d", got.HTTPStatus)
		}

		expectedURL := "https://bouncer.example.com/captcha/challenge?session=session123"
		if got.RedirectURL != expectedURL {
			t.Fatalf("expected redirect URL %s, got %s", expectedURL, got.RedirectURL)
		}

		actualMetrics := r.MetricsService.GetSnapshot()
		wantMetric := crowdsec.Metric{
			Name:  "dropped",
			Unit:  "request",
			Value: 1,
			Labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "captcha",
			},
		}
		metric, ok := actualMetrics["CAPI:captcha"]
		require.True(t, ok, "expected CAPI:captcha metric to exist")
		assert.Equal(t, wantMetric, metric)
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("returns true when bouncer is disabled", func(t *testing.T) {
		cfg := config.Config{
			Bouncer: config.Bouncer{
				Enabled: false,
			},
		}
		b := &Bouncer{
			DecisionCache: nil,
			config:        cfg,
		}

		got := b.IsReady()
		assert.True(t, got, "expected IsReady to return true when bouncer is disabled")
	})

	t.Run("returns false when bouncer enabled but cache is nil", func(t *testing.T) {
		cfg := config.Config{
			Bouncer: config.Bouncer{
				Enabled: true,
			},
		}
		b := &Bouncer{
			DecisionCache: nil,
			config:        cfg,
		}

		got := b.IsReady()
		assert.False(t, got, "expected IsReady to return false when cache is nil")
	})

	t.Run("returns false when cache not synced", func(t *testing.T) {
		mockCache := remediationmocks.NewMockDecisionCache(ctrl)
		mockCache.EXPECT().IsReady().Return(false)

		cfg := config.Config{
			Bouncer: config.Bouncer{
				Enabled: true,
			},
		}
		b := &Bouncer{
			DecisionCache: mockCache,
			config:        cfg,
		}

		got := b.IsReady()
		assert.False(t, got, "expected IsReady to return false when cache not synced")
	})

	t.Run("returns true when cache synced", func(t *testing.T) {
		mockCache := remediationmocks.NewMockDecisionCache(ctrl)
		mockCache.EXPECT().IsReady().Return(true)

		cfg := config.Config{
			Bouncer: config.Bouncer{
				Enabled: true,
			},
		}
		b := &Bouncer{
			DecisionCache: mockCache,
			config:        cfg,
		}

		got := b.IsReady()
		assert.True(t, got, "expected IsReady to return true when cache synced")
	})
}
