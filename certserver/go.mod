module github.com/gke-labs/gateway-api-reference-implementation/certserver

go 1.27.2

require (
	github.com/gke-labs/gateway-api-reference-implementation/certserver/api v0.0.0
	github.com/letsencrypt/pebble/v2 v2.10.1
	github.com/miekg/dns v1.1.73
	github.com/prometheus/client_golang v1.25.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sync v0.24.0
	golang.org/x/time v0.15.0
	google.golang.org/grpc v1.83.2
	sigs.k8s.io/yaml v1.6.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/letsencrypt/challtestsrv v1.4.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/gke-labs/gateway-api-reference-implementation/certserver/api => ./api
