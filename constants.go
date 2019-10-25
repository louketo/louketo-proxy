package main

type contextKey int8

const (
	envPrefix = "PROXY_"

	// defaults proxy endpoints
	authorizationURL = "/authorize"
	callbackURL      = "/callback"
	expiredURL       = "/expired"
	healthURL        = "/health"
	loginURL         = "/login"
	logoutURL        = "/logout"
	metricsURL       = "/metrics"
	tokenURL         = "/token"
	debugURL         = "/debug/pprof"
	refreshURL       = "/refresh"
	traceURL         = "/trace"

	// default claims used to analyze access token
	claimAudience       = "aud"
	claimPreferredName  = "preferred_username"
	claimRealmAccess    = "realm_access"
	claimResourceAccess = "resource_access"
	claimResourceRoles  = "roles"
	claimGroups         = "groups"

	// default cookies names
	accessCookie       = "kc-access"
	refreshCookie      = "kc-state"
	requestURICookie   = "request_uri"
	requestStateCookie = "OAuth_Token_Request_State"

	unsecureScheme = "http"
	secureScheme   = "https"
	anyMethod      = "ANY"
	allRoutes      = "/*"

	_ contextKey = iota
	contextScopeName

	jsonMime            = "application/json; charset=utf-8"
	headerXForwardedFor = "X-Forwarded-For"
	headerXRealIP       = "X-Real-IP"
	authorizationHeader = "Authorization"
	//headerUpgrade       = "Upgrade"
	versionHeader = "X-Auth-Proxy-Version"
)
