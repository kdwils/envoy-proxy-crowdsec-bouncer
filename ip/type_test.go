package ip

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestType(t *testing.T) {
	tests := []struct {
		name string
		addr netip.Addr
		want string
	}{
		{
			name: "ipv4",
			addr: netip.MustParseAddr("192.168.1.100"),
			want: "ipv4",
		},
		{
			name: "ipv6",
			addr: netip.MustParseAddr("2001:db8::1"),
			want: "ipv6",
		},
		{
			name: "ipv4 mapped ipv6 unmaps to ipv4",
			addr: netip.MustParseAddr("::ffff:192.168.1.100"),
			want: "ipv4",
		},
		{
			name: "invalid",
			addr: netip.Addr{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Type(tt.addr))
		})
	}
}

func TestTypeFromPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix netip.Prefix
		want   string
	}{
		{
			name:   "ipv4 prefix",
			prefix: netip.MustParsePrefix("10.0.0.0/8"),
			want:   "ipv4",
		},
		{
			name:   "ipv6 prefix",
			prefix: netip.MustParsePrefix("2001:db8::/32"),
			want:   "ipv6",
		},
		{
			name:   "ipv4 mapped ipv6 prefix unmaps to ipv4",
			prefix: netip.MustParsePrefix("::ffff:10.0.0.0/104"),
			want:   "ipv4",
		},
		{
			name:   "invalid prefix",
			prefix: netip.Prefix{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, TypeFromPrefix(tt.prefix))
		})
	}
}
