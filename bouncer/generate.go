package bouncer

//go:generate mockgen -destination=mocks/mock_bouncer_client.go -package=mocks github.com/kdwils/envoy-gateway-bouncer/bouncer LiveBouncerClient
//go:generate mockgen -destination=mocks/mock_bouncer.go -package=mocks github.com/kdwils/envoy-gateway-bouncer/bouncer Bouncer
