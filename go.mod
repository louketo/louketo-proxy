module github.com/oneconcern/keycloak-gatekeeper

replace github.com/coreos/go-oidc => github.com/coreos/go-oidc v0.0.0-20171020180921-e860bd55bfa7

replace github.com/heptiolabs/healthcheck => github.com/heptiolabs/healthcheck v0.0.0-20180807145615-6ff867650f40

require (
	contrib.go.opencensus.io/exporter/jaeger v0.1.0
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
	github.com/gorilla/csrf v1.6.2
	github.com/gorilla/websocket v1.4.1
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/onsi/ginkgo v1.8.0 // indirect
	github.com/onsi/gomega v1.5.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/prometheus/client_golang v1.1.0
	github.com/rs/cors v1.6.0
	github.com/satori/go.uuid v1.2.0
	github.com/stretchr/testify v1.3.0
	github.com/unrolled/secure v1.0.6
	github.com/urfave/cli v1.22.0
	go.opencensus.io v0.22.0
	go.uber.org/atomic v1.4.0 // indirect
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4
	golang.org/x/net v0.0.0-20190724013045-ca1201d0de80
	golang.org/x/sys v0.0.0-20190804053845-51ab0e2deafa // indirect
	google.golang.org/api v0.7.0 // indirect
	google.golang.org/genproto v0.0.0-20190716160619-c506a9f90610 // indirect
	google.golang.org/grpc v1.22.0 // indirect
	gopkg.in/bsm/ratelimit.v1 v1.0.0-20160220154919-db14e161995a // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/redis.v4 v4.2.4
	gopkg.in/resty.v1 v1.12.0
	gopkg.in/yaml.v2 v2.2.2
)

go 1.13
