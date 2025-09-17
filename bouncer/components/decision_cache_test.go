package components

import (
	"context"
	"sync"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
)

func ptr[T any](v T) *T {
	return &v
}

func TestCrowdSecDecisionCache_GetDecision(t *testing.T) {
	testCache := cache.New[models.Decision]()
	decision := models.Decision{
		Value: ptr("192.168.1.100"),
		Type:  ptr("ban"),
	}
	testCache.Set("192.168.1.100", decision)

	type fields struct {
		stream *csbouncer.StreamBouncer
		cache  *cache.Cache[models.Decision]
		mu     *sync.RWMutex
	}
	type args struct {
		ctx context.Context
		ip  string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *models.Decision
		wantErr bool
	}{
		{
			name: "empty ip",
			fields: fields{
				cache: testCache,
				mu:    &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "nil cache",
			fields: fields{
				mu: &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "192.168.1.1",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "decision found in cache",
			fields: fields{
				cache: testCache,
				mu:    &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "192.168.1.100",
			},
			want:    &decision,
			wantErr: false,
		},
		{
			name: "decision not found in cache",
			fields: fields{
				cache: testCache,
				mu:    &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "192.168.1.99",
			},
			want:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := &CrowdSecDecisionCache{
				stream: tt.fields.stream,
				cache:  tt.fields.cache,
				mu:     tt.fields.mu,
			}
			got, err := dc.GetDecision(tt.args.ctx, tt.args.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("CrowdSecDecisionCache.GetDecision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil && tt.want == nil {
				return
			}
			if got == nil || tt.want == nil {
				t.Errorf("CrowdSecDecisionCache.GetDecision() = %v, want %v", got, tt.want)
				return
			}
			if *got.Value != *tt.want.Value || *got.Type != *tt.want.Type {
				t.Errorf("CrowdSecDecisionCache.GetDecision() = %v, want %v", got, tt.want)
			}
		})
	}
}
