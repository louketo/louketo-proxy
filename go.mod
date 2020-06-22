module github.com/oneconcern/keycloak-gatekeeper

replace github.com/coreos/go-oidc => github.com/coreos/go-oidc v0.0.0-20171020180921-e860bd55bfa7

replace github.com/heptiolabs/healthcheck => github.com/heptiolabs/healthcheck v0.0.0-20180807145615-6ff867650f40

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.0
	github.com/DataDog/opencensus-go-exporter-datadog v0.0.0-20200406135749-5c268882acf0
	github.com/PuerkitoBio/purell v1.1.1
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/armon/go-proxyproto v0.0.0-20190211145416-68259f75880e
	github.com/boltdb/bolt v1.3.1
	github.com/coreos/go-oidc v0.0.0-00010101000000-000000000000
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/elazarl/goproxy v0.0.0-20190711103511-473e67f1d7d2
	github.com/elazarl/goproxy/ext v0.0.0-20190711103511-473e67f1d7d2 // indirect
	github.com/fsnotify/fsnotify v1.4.7
	github.com/garyburd/redigo v1.6.0 // indirect
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/csrf v1.7.0
	github.com/gorilla/websocket v1.4.2
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/onsi/ginkgo v1.8.0 // indirect
	github.com/onsi/gomega v1.5.0 // indirect
	github.com/prometheus/client_golang v1.7.0
	github.com/rs/cors v1.7.0
	github.com/satori/go.uuid v1.2.0
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/uber/jaeger-client-go v2.24.0+incompatible // indirect
	github.com/unrolled/secure v1.0.6
	github.com/urfave/cli v1.22.0
	go.opencensus.io v0.22.4
	go.uber.org/zap v1.15.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e
	google.golang.org/api v0.28.0 // indirect
	gopkg.in/bsm/ratelimit.v1 v1.0.0-20160220154919-db14e161995a // indirect
	gopkg.in/redis.v4 v4.2.4
	gopkg.in/resty.v1 v1.12.0
	gopkg.in/yaml.v2 v2.2.5
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
)

go 1.14
