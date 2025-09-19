package bouncer

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	remediationmocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func parseCIDROrFail(t *testing.T, cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("failed to parse CIDR %q: %v", cidr, err)
	}
	return ipnet
}

func TestExtractRealIP(t *testing.T) {
	trusted := []*net.IPNet{
		parseCIDROrFail(t, "10.0.0.0/8"),
		parseCIDROrFail(t, "192.168.0.0/16"),
	}

	tests := []struct {
		name           string
		ip             string
		headers        map[string]string
		trustedProxies []*net.IPNet
		want           string
	}{
		{
			name: "No headers, returns socket IP",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"foo": "bar",
			},
			trustedProxies: nil,
			want:           "1.2.3.4",
		},
		{
			name: "x-real-ip present and valid",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"x-real-ip": "5.6.7.8",
			},
			trustedProxies: nil,
			want:           "5.6.7.8",
		},
		{
			name: "x-real-ip present but invalid, fallback to socket IP",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"x-real-ip": "not-an-ip",
			},
			trustedProxies: nil,
			want:           "1.2.3.4",
		},
		{
			name: "x-forwarded-for, no trusted proxies, picks last valid",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"x-forwarded-for": "10.0.0.1, 8.8.8.8, 9.9.9.9",
			},
			trustedProxies: nil,
			want:           "9.9.9.9",
		},
		{
			name: "x-forwarded-for, skips trusted proxies",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"x-forwarded-for": "10.0.0.1, 192.168.1.1, 8.8.8.8",
			},
			trustedProxies: trusted,
			want:           "8.8.8.8",
		},
		{
			name: "x-forwarded-for, all trusted, fallback to socket IP",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1, 192.168.1.1",
			},
			trustedProxies: trusted,
			want:           "1.2.3.4",
		},
		{
			name: "x-forwarded-for, some invalid IPs, picks valid",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip, 8.8.8.8",
			},
			trustedProxies: nil,
			want:           "8.8.8.8",
		},
		{
			name: "x-forwarded-for, more than 20 IPs, only last 20 considered",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"X-Forwarded-For": "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8,9.9.9.9,10.10.10.10,11.11.11.11,12.12.12.12,13.13.13.13,14.14.14.14,15.15.15.15,16.16.16.16,17.17.17.17,18.18.18.18,19.19.19.19,20.20.20.20,21.21.21.21,22.22.22.22",
			},
			trustedProxies: nil,
			want:           "22.22.22.22",
		},
		{
			name: "x-forwarded-for header case-insensitive",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"x-Forwarded-For": "8.8.8.8",
			},
			trustedProxies: nil,
			want:           "8.8.8.8",
		},
		{
			name: "x-forwarded-for with spaces",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"X-Forwarded-For": " 10.0.0.1 , 8.8.8.8 ",
			},
			trustedProxies: nil,
			want:           "8.8.8.8",
		},
		{
			name: "x-forwarded-for, all invalid, fallback to x-real-ip",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip, also-bad",
				"x-real-ip":       "5.5.5.5",
			},
			trustedProxies: nil,
			want:           "5.5.5.5",
		},
		{
			name: "x-forwarded-for, all invalid, fallback to socket IP",
			ip:   "1.2.3.4",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip, also-bad",
			},
			trustedProxies: nil,
			want:           "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRealIP(tt.ip, tt.headers, tt.trustedProxies)
			if got != tt.want {
				t.Errorf("extractRealIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
func TestIsTrustedProxy(t *testing.T) {
	trusted := []*net.IPNet{
		parseCIDROrFail(t, "10.0.0.0/8"),
		parseCIDROrFail(t, "192.168.0.0/16"),
		parseCIDROrFail(t, "2001:db8::/32"),
	}

	tests := []struct {
		name           string
		ip             string
		trustedProxies []*net.IPNet
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

func TestParseProxyAddresses(t *testing.T) {
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
			got, err := parseProxyAddresses(tt.input)
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
	trusted := []*net.IPNet{
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
			want: &ParsedRequest{Headers: map[string]string{}},
		},
		{
			name: "nil attributes returns empty ParsedRequest",
			req:  &auth.CheckRequest{},
			want: &ParsedRequest{Headers: map[string]string{}},
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
				IP:     "5.6.7.8",
				RealIP: "5.6.7.8",
				Headers: map[string]string{
					":scheme":         "https",
					":authority":      "example.com",
					":path":           "/foo/bar",
					":method":         "GET",
					"user-agent":      "TestAgent",
					"some-header":     "some-value",
					"x-forwarded-for": "10.0.0.1,5.6.7.8",
				},
				URL:        url.URL{Scheme: "https", Host: "example.com", Path: "/foo/bar"},
				Method:     "GET",
				UserAgent:  "TestAgent",
				Body:       []byte("bodydata"),
				ProtoMajor: 1,
				ProtoMinor: 1,
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
				IP:     "2.2.2.2",
				RealIP: "2.2.2.2",
				Headers: map[string]string{
					":scheme":    "http",
					":authority": "host.com",
					":path":      "/baz",
					":method":    "POST",
					"user-agent": "UA-From-Headers",
				},
				URL:        url.URL{Scheme: "http", Host: "host.com", Path: "/baz"},
				Method:     "POST",
				UserAgent:  "UA-From-Headers",
				Body:       []byte(""),
				ProtoMajor: 2,
				ProtoMinor: 0,
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
				IP:     "3.3.3.3",
				RealIP: "3.3.3.3",
				Headers: map[string]string{
					":scheme":    "http",
					":authority": "nested.com",
					":path":      "/nested",
					":method":    "PUT",
					"foo":        "bar",
				},
				URL:        url.URL{Scheme: "http", Host: "nested.com", Path: "/nested"},
				Method:     "PUT",
				UserAgent:  "",
				Body:       []byte("abc"),
				ProtoMajor: 2,
				ProtoMinor: 0,
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
				IP:     "4.4.4.4",
				RealIP: "8.8.8.8",
				Headers: map[string]string{
					":scheme":         "http",
					":authority":      "xff.com",
					":path":           "/xff",
					":method":         "GET",
					"x-forwarded-for": "10.0.0.1, 8.8.8.8",
				},
				URL:        url.URL{Scheme: "http", Host: "xff.com", Path: "/xff"},
				Method:     "GET",
				UserAgent:  "",
				Body:       []byte(""),
				ProtoMajor: 1,
				ProtoMinor: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.ParseCheckRequest(context.Background(), tt.req)
			if got.IP != tt.want.IP ||
				got.RealIP != tt.want.RealIP ||
				got.Method != tt.want.Method ||
				got.UserAgent != tt.want.UserAgent ||
				got.URL != tt.want.URL ||
				got.ProtoMajor != tt.want.ProtoMajor ||
				got.ProtoMinor != tt.want.ProtoMinor ||
				!reflect.DeepEqual(got.Headers, tt.want.Headers) ||
				!reflect.DeepEqual(got.Body, tt.want.Body) {
				t.Errorf("ParseCheckRequest() = %+v, want %+v", got, tt.want)
			}
		})
	}
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
		r := Bouncer{DecisionCache: mb, WAF: mw, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("1.2.3.4", "http", "example.com", "/foo", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "1.2.3.4").Return(&models.Decision{Type: ptr("ban")}, nil)
		// WAF should not be called when bouncer denies

		got := r.Check(context.Background(), req)
		want := CheckedRequest{IP: "1.2.3.4", Action: "deny", Reason: "unknown decision cache action", HTTPStatus: 403}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}

		expectedMetrics := Metrics{
			Remediation: map[string]RemediationMetrics{
				"envoy-proxy-bouncer:processed": {Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed", Count: 1},
				"crowdsec:ban":                  {Name: "requests", Origin: "crowdsec", RemediationType: "ban", Count: 1},
			},
		}
		actualMetrics := r.GetMetrics()
		if !reflect.DeepEqual(actualMetrics, expectedMetrics) {
			t.Errorf("metrics mismatch:\nexpected: %+v\nactual: %+v", expectedMetrics, actualMetrics)
		}
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("5.6.7.8", "http", "example.com", "/foo", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "5.6.7.8").Return(nil, fmt.Errorf("boom"))

		got := r.Check(context.Background(), req)
		want := CheckedRequest{IP: "5.6.7.8", Action: "deny", Reason: "decision cache error", HTTPStatus: 403}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}

		expectedMetrics := Metrics{
			Remediation: map[string]RemediationMetrics{
				"envoy-proxy-bouncer:processed": {Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed", Count: 1},
				"crowdsec:error":                {Name: "requests", Origin: "crowdsec", RemediationType: "error", Count: 1},
			},
		}
		actualMetrics := r.GetMetrics()
		if !reflect.DeepEqual(actualMetrics, expectedMetrics) {
			t.Errorf("metrics mismatch:\nexpected: %+v\nactual: %+v", expectedMetrics, actualMetrics)
		}
	})

	t.Run("waf denies after bouncer allows", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("9.9.9.9", "https", "host", "/bar", "POST", "HTTP/2", "abc")

		mb.EXPECT().GetDecision(gomock.Any(), "9.9.9.9").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "ban"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "ban" || got.Reason != "ban" || got.HTTPStatus != 403 || got.IP != "9.9.9.9" {
			t.Fatalf("unexpected result: %+v", got)
		}

		expectedMetrics := Metrics{
			Remediation: map[string]RemediationMetrics{
				"envoy-proxy-bouncer:processed": {Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed", Count: 1},
				"crowdsec:ban":                  {Name: "requests", Origin: "crowdsec", RemediationType: "ban", Count: 1},
			},
		}
		actualMetrics := r.GetMetrics()
		if !reflect.DeepEqual(actualMetrics, expectedMetrics) {
			t.Errorf("metrics mismatch:\nexpected: %+v\nactual: %+v", expectedMetrics, actualMetrics)
		}
	})

	t.Run("waf error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("10.0.0.1", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "10.0.0.1").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{}, fmt.Errorf("waf down"))

		got := r.Check(context.Background(), req)
		if got.Action != "error" || got.Reason != "error" || got.HTTPStatus != 500 || got.IP != "10.0.0.1" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("allow both", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("7.7.7.7", "https", "ex", "/ok", "GET", "HTTP/2", "")

		mb.EXPECT().GetDecision(gomock.Any(), "7.7.7.7").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "allow"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "allow" || got.Reason != "ok" || got.HTTPStatus != 200 || got.IP != "7.7.7.7" {
			t.Fatalf("unexpected result: %+v", got)
		}

		// Verify metrics: 1 processed request (allowed through)
		expectedMetrics := Metrics{
			Remediation: map[string]RemediationMetrics{
				"envoy-proxy-bouncer:processed": {Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed", Count: 1},
			},
		}
		actualMetrics := r.GetMetrics()
		if !reflect.DeepEqual(actualMetrics, expectedMetrics) {
			t.Errorf("metrics mismatch:\nexpected: %+v\nactual: %+v", expectedMetrics, actualMetrics)
		}
	})

	t.Run("waf denies with deny action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("8.8.8.8", "https", "host", "/bar", "POST", "HTTP/2", "abc")

		mb.EXPECT().GetDecision(gomock.Any(), "8.8.8.8").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "deny"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "deny" || got.Reason != "ban" || got.HTTPStatus != 403 || got.IP != "8.8.8.8" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("waf returns error action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("11.11.11.11", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "11.11.11.11").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "error"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "error" || got.Reason != "ban" || got.HTTPStatus != 403 || got.IP != "11.11.11.11" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("waf returns unknown action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("12.12.12.12", "http", "h", "/p", "GET", "HTTP/1.0", "")

		mb.EXPECT().GetDecision(gomock.Any(), "12.12.12.12").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "unknown"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "unknown" || got.Reason != "unknown action" || got.HTTPStatus != 500 || got.IP != "12.12.12.12" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("waf disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: nil, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("13.13.13.13", "https", "ex", "/ok", "GET", "HTTP/2", "")

		mb.EXPECT().GetDecision(gomock.Any(), "13.13.13.13").Return(nil, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "allow" || got.Reason != "ok" || got.HTTPStatus != 200 || got.IP != "13.13.13.13" {
			t.Fatalf("unexpected result: %+v", got)
		}
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
		r := Bouncer{DecisionCache: nil, WAF: nil, CaptchaService: nil, metrics: cache.New[RemediationMetrics]()}
		req := mkReq("1.1.1.1", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		got := r.Check(context.Background(), req)
		if got.Action != "allow" || got.Reason != "ok" || got.HTTPStatus != 200 || got.IP != "1.1.1.1" {
			t.Fatalf("unexpected result: %+v", got)
		}

		// Verify metrics: 1 processed request (everything disabled)
		expectedMetrics := Metrics{
			Remediation: map[string]RemediationMetrics{
				"envoy-proxy-bouncer:processed": {Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed", Count: 1},
			},
		}
		actualMetrics := r.GetMetrics()
		if !reflect.DeepEqual(actualMetrics, expectedMetrics) {
			t.Errorf("metrics mismatch:\nexpected: %+v\nactual: %+v", expectedMetrics, actualMetrics)
		}
	})

	t.Run("bouncer denies - short circuit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("2.2.2.2", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "2.2.2.2").Return(&models.Decision{Type: ptr("ban")}, nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{IP: "2.2.2.2", Action: "deny", Reason: "unknown decision cache action", HTTPStatus: 403}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("bouncer error - short circuit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("3.3.3.3", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "3.3.3.3").Return(nil, fmt.Errorf("bouncer failed"))

		got := r.Check(context.Background(), req)
		want := CheckedRequest{IP: "3.3.3.3", Action: "deny", Reason: "decision cache error", HTTPStatus: 403}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("bouncer allows - waf denies", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("4.4.4.4", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "4.4.4.4").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "deny"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "deny" || got.Reason != "ban" || got.HTTPStatus != 403 || got.IP != "4.4.4.4" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf bans", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("5.5.5.5", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "5.5.5.5").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "ban"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "ban" || got.Reason != "ban" || got.HTTPStatus != 403 || got.IP != "5.5.5.5" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf errors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("6.6.6.6", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "6.6.6.6").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{}, fmt.Errorf("waf connection failed"))

		got := r.Check(context.Background(), req)
		if got.Action != "error" || got.Reason != "error" || got.HTTPStatus != 500 || got.IP != "6.6.6.6" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf returns error action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("7.7.7.7", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "7.7.7.7").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "error"}, nil)

		got := r.Check(context.Background(), req)
		if got.Action != "error" || got.Reason != "ban" || got.HTTPStatus != 403 || got.IP != "7.7.7.7" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf unknown action", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

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
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

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
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("10.10.10.10", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "10.10.10.10").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(false)

		got := r.Check(context.Background(), req)
		if got.Action != "allow" || got.Reason != "captcha disabled" || got.HTTPStatus != 200 || got.IP != "10.10.10.10" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("bouncer allows - waf captcha - captcha nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: nil, metrics: cache.New[RemediationMetrics]()}

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
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("12.12.12.12", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "12.12.12.12").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().GenerateChallengeURL("12.12.12.12", "https://example.com/test").Return("", nil)

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
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("13.13.13.13", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "13.13.13.13").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().GenerateChallengeURL("13.13.13.13", "https://example.com/test").Return("", fmt.Errorf("session creation failed"))

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
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("14.14.14.14", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "14.14.14.14").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().GenerateChallengeURL("14.14.14.14", "https://example.com/test").Return("https://bouncer.example.com/captcha/challenge?session=abc123", nil)

		got := r.Check(context.Background(), req)
		if got.Action != "captcha" || got.Reason != "captcha required" || got.HTTPStatus != 302 || got.IP != "14.14.14.14" || got.RedirectURL != "https://bouncer.example.com/captcha/challenge?session=abc123" {
			t.Fatalf("unexpected result: %+v", got)
		}

		expectedMetrics := Metrics{
			Remediation: map[string]RemediationMetrics{
				"envoy-proxy-bouncer:processed": {Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed", Count: 1},
				"crowdsec:captcha":              {Name: "requests", Origin: "crowdsec", RemediationType: "captcha", Count: 1},
			},
		}
		actualMetrics := r.GetMetrics()
		if !reflect.DeepEqual(actualMetrics, expectedMetrics) {
			t.Errorf("metrics mismatch:\nexpected: %+v\nactual: %+v", expectedMetrics, actualMetrics)
		}
	})

	t.Run("bouncer captcha - direct to captcha flow", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mb := remediationmocks.NewMockDecisionCache(ctrl)
		mw := remediationmocks.NewMockWAF(ctrl)
		mc := remediationmocks.NewMockCaptchaService(ctrl)
		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("15.15.15.15", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "15.15.15.15").Return(&models.Decision{Type: ptr("captcha")}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().GenerateChallengeURL("15.15.15.15", "https://example.com/test").Return("https://bouncer.example.com/captcha/challenge?session=crowdsec123", nil)

		got := r.Check(context.Background(), req)
		want := CheckedRequest{
			IP:          "15.15.15.15",
			Action:      "captcha",
			Reason:      "captcha required",
			HTTPStatus:  302,
			RedirectURL: "https://bouncer.example.com/captcha/challenge?session=crowdsec123",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}

		expectedMetrics := Metrics{
			Remediation: map[string]RemediationMetrics{
				"envoy-proxy-bouncer:processed": {Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed", Count: 1},
				"crowdsec:captcha":              {Name: "requests", Origin: "crowdsec", RemediationType: "captcha", Count: 1},
			},
		}
		actualMetrics := r.GetMetrics()
		if !reflect.DeepEqual(actualMetrics, expectedMetrics) {
			t.Errorf("metrics mismatch:\nexpected: %+v\nactual: %+v", expectedMetrics, actualMetrics)
		}
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

		r := Bouncer{DecisionCache: mb, WAF: mw, CaptchaService: mc, metrics: cache.New[RemediationMetrics]()}

		req := mkReq("1.2.3.4", "https", "example.com", "/test", "GET", "HTTP/1.1", "")

		mb.EXPECT().GetDecision(gomock.Any(), "1.2.3.4").Return(nil, nil)
		mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
		mc.EXPECT().IsEnabled().Return(true)
		mc.EXPECT().GenerateChallengeURL("1.2.3.4", "https://example.com/test").Return("https://bouncer.example.com/captcha/challenge?session=session123", nil)

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

		expectedMetrics := Metrics{
			Remediation: map[string]RemediationMetrics{
				"envoy-proxy-bouncer:processed": {Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed", Count: 1},
				"crowdsec:captcha":              {Name: "requests", Origin: "crowdsec", RemediationType: "captcha", Count: 1},
			},
		}
		actualMetrics := r.GetMetrics()
		if !reflect.DeepEqual(actualMetrics, expectedMetrics) {
			t.Errorf("metrics mismatch:\nexpected: %+v\nactual: %+v", expectedMetrics, actualMetrics)
		}
	})
}

func TestBouncer_CalculateMetrics_FieldStructure(t *testing.T) {
	r := Bouncer{metrics: cache.New[RemediationMetrics]()}

	r.IncRemediationMetric(MetricLabels{Name: "requests", Origin: "envoy-proxy-bouncer", RemediationType: "processed"})
	r.IncRemediationMetric(MetricLabels{Name: "requests", Origin: "crowdsec", RemediationType: "ban"})
	r.IncRemediationMetric(MetricLabels{Name: "requests", Origin: "crowdsec", RemediationType: "captcha"})

	allMetrics := r.CalculateMetrics(10 * time.Second)

	require.Len(t, allMetrics.RemediationComponents, 1)
	component := allMetrics.RemediationComponents[0]
	require.Len(t, component.Metrics, 1)

	detailedMetrics := component.Metrics[0]
	require.Len(t, detailedMetrics.Items, 3)

	itemsByUnit := make(map[string]*models.MetricsDetailItem)
	for _, item := range detailedMetrics.Items {
		itemsByUnit[*item.Unit] = item
	}

	processedItem := itemsByUnit["processed"]
	require.NotNil(t, processedItem)
	require.Equal(t, "requests", *processedItem.Name)
	require.Equal(t, "processed", *processedItem.Unit)
	require.Equal(t, float64(1), *processedItem.Value)
	require.Equal(t, "envoy-proxy-bouncer", processedItem.Labels["origin"])
	require.Equal(t, "processed", processedItem.Labels["remediation"])

	banItem := itemsByUnit["ban"]
	require.NotNil(t, banItem)
	require.Equal(t, "requests", *banItem.Name)
	require.Equal(t, "ban", *banItem.Unit)
	require.Equal(t, float64(1), *banItem.Value)
	require.Equal(t, "crowdsec", banItem.Labels["origin"])
	require.Equal(t, "ban", banItem.Labels["remediation"])

	captchaItem := itemsByUnit["captcha"]
	require.NotNil(t, captchaItem)
	require.Equal(t, "requests", *captchaItem.Name)
	require.Equal(t, "captcha", *captchaItem.Unit)
	require.Equal(t, float64(1), *captchaItem.Value)
	require.Equal(t, "crowdsec", captchaItem.Labels["origin"])
	require.Equal(t, "captcha", captchaItem.Labels["remediation"])
}
