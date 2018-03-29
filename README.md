[![Build Status](https://travis-ci.org/gambol99/keycloak-proxy.svg?branch=master)](https://travis-ci.org/gambol99/keycloak-proxy)
[![GoDoc](http://godoc.org/github.com/gambol99/keycloak-proxy?status.png)](http://godoc.org/github.com/gambol99/keycloak-proxy)
[![Docker Repository on Quay](https://quay.io/repository/gambol99/keycloak-proxy/status "Docker Repository on Quay")](https://quay.io/repository/gambol99/keycloak-proxy)
[![GitHub version](https://badge.fury.io/gh/gambol99%2Fkeycloak-proxy.svg)](https://badge.fury.io/gh/gambol99%2Fkeycloak-proxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/gambol99/keycloak-proxy)](https://goreportcard.com/report/github.com/gambol99/keycloak-proxy)
[![Coverage Status](https://coveralls.io/repos/github/gambol99/keycloak-proxy/badge.svg?branch=master)](https://coveralls.io/github/gambol99/keycloak-proxy?branch=master)

### **Keycloak Proxy**
----

  - Supports role based uri controls
  - Web Socket connection upgrading
  - Token claim matching for additional ACL controls
  - Custom claim injections into authenticated requests
  - Stateless offline refresh tokens with optional predefined session limits
  - TLS and mutual TLS support
  - JSON field bases access logs
  - Custom Sign-in and access forbidden pages
  - Forward Signed Proxy
  - URL Role Tokenization
  - Listen on unix sockets, proxy upstream to unix sockets
  - Let's Encrypt support

----

Keycloak-proxy is a proxy service which at the risk of stating the obvious integrates with the [Keycloak](https://github.com/keycloak/keycloak) authentication service. Although technically the service has no dependency on Keycloak itself and would quite happily work with any OpenID provider. The service supports both access tokens in browser cookie or bearer tokens.

```shell
$ bin/keycloak-proxy help
NAME:
   keycloak-proxy - is a proxy using the keycloak service for auth and authorization

USAGE:
   keycloak-proxy [options]

VERSION:
   v2.1.1 (git+sha: 35e834a, built: 02-03-2018)

AUTHOR:
   Rohith <gambol99@gmail.com>

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --config value                            path the a configuration file [$PROXY_CONFIG_FILE]
   --listen value                            the interface the service should be listening on [$PROXY_LISTEN]
   --listen-http value                       interface we should be listening [$PROXY_LISTEN_HTTP]
   --discovery-url value                     discovery url to retrieve the openid configuration [$PROXY_DISCOVERY_URL]
   --client-id value                         client id used to authenticate to the oauth service [$PROXY_CLIENT_ID]
   --client-secret value                     client secret used to authenticate to the oauth service [$PROXY_CLIENT_SECRET]
   --redirection-url value                   redirection url for the oauth callback url, defaults to host header is absent [$PROXY_REDIRECTION_URL]
   --revocation-url value                    url for the revocation endpoint to revoke refresh token [$PROXY_REVOCATION_URL]
   --skip-openid-provider-tls-verify         skip the verification of any TLS communication with the openid provider (default: false)
   --openid-provider-proxy value             proxy for communication with the openid provider
   --openid-provider-timeout value           timeout for openid configuration on .well-known/openid-configuration (default: 30s)
   --scopes value                            list of scopes requested when authenticating the user
   --upstream-url value                      url for the upstream endpoint you wish to proxy [$PROXY_UPSTREAM_URL]
   --upstream-ca value                       the path to a file container a CA certificate to validate the upstream tls endpoint
   --resources value                         list of resources 'uri=/admin*|methods=GET,PUT|roles=role1,role2'
   --headers value                           custom headers to the upstream request, key=value
   --enable-default-deny                     enables a default denial on all requests, you have to explicitly say what is permitted (recommended) (default: false)
   --enable-encrypted-token                  enable encryption for the access tokens (default: false)
   --enable-logging                          enable http logging of the requests (default: false)
   --enable-json-logging                     switch on json logging rather than text (default: false)
   --enable-forwarding                       enables the forwarding proxy mode, signing outbound request (default: false)
   --enable-security-filter                  enables the security filter handler (default: false) [$PROXY_ENABLE_SECURITY_FILTER]
   --enable-refresh-tokens                   enables the handling of the refresh tokens (default: false) [$PROXY_ENABLE_REFRESH_TOKEN]
   --enable-login-handler                    enables the handling of the refresh tokens (default: false) [$PROXY_ENABLE_LOGIN_HANDLER]
   --enable-token-header                     enables the token authentication header X-Auth-Token to upstream (default: true)
   --enable-authorization-header             adds the authorization header to the proxy request (default: true) [$PROXY_ENABLE_AUTHORIZATION_HEADER]
   --enable-authorization-cookies            adds the authorization cookies to the uptream proxy request (default: true) [$PROXY_ENABLE_AUTHORIZATION_COOKIES]
   --enable-https-redirection                enable the http to https redirection on the http service (default: false)
   --enable-profiling                        switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc (default: false)
   --enable-metrics                          enable the prometheus metrics collector on /oauth/metrics (default: false)
   --filter-browser-xss                      enable the adds the X-XSS-Protection header with mode=block (default: false)
   --filter-content-nosniff                  adds the X-Content-Type-Options header with the value nosniff (default: false)
   --filter-frame-deny                       enable to the frame deny header (default: false)
   --content-security-policy value           specify the content security policy
   --localhost-metrics                       enforces the metrics page can only been requested from 127.0.0.1 (default: false)
   --access-token-duration value             fallback cookie duration for the access token when using refresh tokens (default: 720h0m0s)
   --cookie-domain value                     domain the access cookie is available to, defaults host header
   --cookie-access-name value                name of the cookie use to hold the access token (default: "kc-access")
   --cookie-refresh-name value               name of the cookie used to hold the encrypted refresh token (default: "kc-state")
   --secure-cookie                           enforces the cookie to be secure (default: true)
   --http-only-cookie                        enforces the cookie is in http only mode (default: false)
   --match-claims value                      keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*
   --add-claims value                        extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name
   --tls-cert value                          path to ths TLS certificate
   --tls-private-key value                   path to the private key for TLS
   --tls-ca-certificate value                path to the ca certificate used for signing requests
   --tls-ca-key value                        path the ca private key, used by the forward signing proxy
   --tls-client-certificate value            path to the client certificate for outbound connections in reverse and forwarding proxy modes
   --skip-upstream-tls-verify                skip the verification of any upstream TLS (default: true)
   --skip-client-id                          skip the check on the client token (default: false)
   --cors-origins value                      origins to add to the CORE origins control (Access-Control-Allow-Origin)
   --cors-methods value                      methods permitted in the access control (Access-Control-Allow-Methods)
   --cors-headers value                      set of headers to add to the CORS access control (Access-Control-Allow-Headers)
   --cors-exposed-headers value              expose cors headers access control (Access-Control-Expose-Headers)
   --cors-credentials                        credentials access control header (Access-Control-Allow-Credentials) (default: false)
   --cors-max-age value                      max age applied to cors headers (Access-Control-Max-Age) (default: 0s)
   --hostnames value                         list of hostnames the service will respond to
   --store-url value                         url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file
   --encryption-key value                    encryption key used to encryption the session state [$PROXY_ENCRYPTION_KEY]
   --no-redirects                            do not have back redirects when no authentication is present, 401 them (default: false)
   --skip-token-verification                 TESTING ONLY; bypass token verification, only expiration and roles enforced (default: false)
   --upstream-keepalives                     enables or disables the keepalive connections for upstream endpoint (default: true)
   --upstream-timeout value                  maximum amount of time a dial will wait for a connect to complete (default: 10s)
   --upstream-keepalive-timeout value        specifies the keep-alive period for an active network connection (default: 10s)
   --upstream-tls-handshake-timeout value    the timeout placed on the tls handshake for upstream (default: 10s)
   --upstream-response-header-timeout value  the timeout placed on the response header for upstream (default: 1s)
   --upstream-expect-continue-timeout value  the timeout placed on the expect continue for upstream (default: 10s)
   --verbose                                 switch on debug / verbose logging (default: false)
   --enabled-proxy-protocol                  enable proxy protocol (default: false)
   --server-read-timeout value               the server read timeout on the http server (default: 5s)
   --server-write-timeout value              the server write timeout on the http server (default: 10s)
   --server-idle-timeout value               the server idle timeout on the http server (default: 2m0s)
   --use-letsencrypt                         use letsencrypt for certificates (default: false)
   --letsencrypt-cache-dir value             path where cached letsencrypt certificates are stored (default: "./cache/")
   --sign-in-page value                      path to custom template displayed for signin
   --forbidden-page value                    path to custom template used for access forbidden
   --tags value                              keypairs passed to the templates at render,e.g title=Page
   --forwarding-username value               username to use when logging into the openid provider
   --forwarding-password value               password to use when logging into the openid provider
   --forwarding-domains value                list of domains which should be signed; everything else is relayed unsigned
   --disable-all-logging                     disables all logging to stdout and stderr (default: false)
   --help, -h                                show help
   --version, -v                             print the version
```

#### **Building**

Assuming you have make + go, simply run make (or 'make static' for static linking). You can also build via docker container: make docker-build

#### **Docker image**
Docker image is available at [https://quay.io/repository/gambol99/keycloak-proxy](https://quay.io/repository/gambol99/keycloak-proxy)


#### **Configuration**

Configuration can come from a yaml/json file and or the command line options (note, command options have a higher priority and will override or merge any options referenced in a config file)

```YAML
# is the url for retrieve the OpenID configuration - normally the <server>/auth/realm/<realm_name>
discovery-url: https://keycloak.example.com/auth/realms/<REALM_NAME>
# the client id for the 'client' application
client-id: <CLIENT_ID>
# the secret associated to the 'client' application
client-secret: <CLIENT_SECRET>
# the interface definition you wish the proxy to listen, all interfaces is specified as ':<port>', unix sockets as unix://<REL_PATH>|</ABS PATH>
listen: 127.0.0.1:3000
# whether to enable refresh tokens
enable-refresh-tokens: true
# the location of a certificate you wish the proxy to use for TLS support
tls-cert:
# the location of a private key for TLS
tls-private-key:
# the redirection url, essentially the site url, note: /oauth/callback is added at the end
redirection-url: http://127.0.0.1:3000
# the encryption key used to encode the session state
encryption-key: <ENCRYPTION_KEY>
# the upstream endpoint which we should proxy request
upstream-url: http://127.0.0.1:80
# additional scopes to add to add to the default (openid+email+profile)
scopes:
- vpn-user
# a collection of resource i.e. urls that you wish to protect
resources:
- uri: /admin/test
  # the methods on this url that should be protected, if missing, we assuming all
  methods:
  - GET
  # a list of roles the user must have in order to access urls under the above
  # If all you want is authentication ONLY, simply remove the roles array - the user must be authenticated but
  # no roles are required
  roles:
  - openvpn:vpn-user
  - openvpn:prod-vpn
  - test
- uri: /admin/*
  methods:
  - GET
  roles:
  - openvpn:vpn-user
  - openvpn:commons-prod-vpn
```

#### **Example Usage**

Assuming you have some web service you wish protected by Keycloak;

* Create the *client* under the Keycloak GUI or CLI; the client protocol is *'openid-connect'*, access-type:  *confidential*.
* Add a Valid Redirect URIs of *http://127.0.0.1:3000/oauth/callback*.
* Grab the client id and client secret.
* Create the various roles under the client or existing clients for authorization purposes.

##### **- A configuration**

```YAML
client-id: <CLIENT_ID>
client-secret: <CLIENT_SECRET> # require for access_type: confidential
# Note the redirection-url is optional, it will default to the X-Forwarded-Proto / X-Forwarded-Host r the URL scheme and host not found
discovery-url: https://keycloak.example.com/auth/realms/<REALM_NAME>
enable-default-deny: true
encryption_key: AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j
listen: 127.0.0.1:3000
redirection-url: http://127.0.0.1:3000
upstream-url: http://127.0.0.1:80
resources:
- uri: /admin*
  methods:
  - GET
  roles:
  - client:test1
  - client:test2
  groups:
  - admins
  - users
- uri: /backend*
  roles:
  - client:test1
- uri: /public/*
  white-listed: true
- uri: /favicon
  white-listed: true
- uri: /css/*
  white-listed: true
- uri: /img/*
  white-listed: true
```

Note, anything defined in the configuration file can also be configured as command line options, so the above would be reflected as;

```shell
bin/keycloak-proxy \
    --discovery-url=https://keycloak.example.com/auth/realms/<REALM_NAME> \
    --client-id=<CLIENT_ID> \
    --client-secret=<SECRET> \
    --listen=127.0.0.1:3000 \ # unix sockets format unix://path
    --redirection-url=http://127.0.0.1:3000 \
    --enable-refresh-tokens=true \
    --encryption-key=AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j \
    --upstream-url=http://127.0.0.1:80 \
    --enable-default-deny=true \
    --resources="uri=/admin*|roles=test1,test2" \
    --resources="uri=/backend*|roles=test1" \
    --resources="uri=/css/*|white-listed=true" \
    --resources="uri=/img/*|white-listed=true" \
    --resources="uri=/public/*|white-listed=true"
```

The **recommended** deployment to use a default denial to all requests via `--enable-default-deny=true` or `--resources="uri=/*"` and to then explicityly allow what you want through.

#### **HTTP Routing**

By default all requests will be proxyed on to the upstream, if you wish to ensure all requests are authentication you can use

```shell
--resource=uri=/* # note, by default unless specified the methods is assumed to be 'any|ANY'
```

Note the HTTP routing rules following the guidelines from [chi](https://github.com/go-chi/chi#router-design). Its also worth nothing the ordering of the resource do not matter, the router will handle that for you.

#### **Google OAuth**

Although the role extensions do require a Keycloak IDP or at the very least a IDP that produces a token which contains roles, there's nothing stopping you from using it against any OpenID providers, such as Google. Go to the Google Developers Console/Google Cloud Console and create a new OAuth 2.0 client ID *(via "API Manager-> Credentials)*. Once you've created the OAuth 2.0 client ID, take the client ID, secret and make sure you've added the callback url to the application scope *(using the default this would be http://127.0.0.1:3000/oauth/callback)*

```shell
bin/keycloak-proxy \
  --discovery-url=https://accounts.google.com/.well-known/openid-configuration \
  --client-id=<CLIENT_ID> \
  --client-secret=<CLIENT_SECRET> \
  --resources="uri=/*" \
  --verbose=true
```

Open a browser an go to http://127.0.0.1:3000 and you should be redirected to Google for authenticate and back the application when done and you should see something like the below.

```shell
DEBU[0002] resource access permitted: /                  access=permitted bearer=false expires=57m51.32029042s resource=/ username=gambol99@gmail.com
2016-02-06 13:59:01.680300 I | http: proxy error: dial tcp 127.0.0.1:8081: getsockopt: connection refused
DEBU[0002] resource access permitted: /favicon.ico       access=permitted bearer=false expires=57m51.144004098s resource=/ username=gambol99@gmail.com
2016-02-06 13:59:01.856716 I | http: proxy error: dial tcp 127.0.0.1:8081: getsockopt: connection refused
```

#### **Forward Signing Proxy**

Forward signing provides a mechanism for authentication and authorization between services using tokens issued from the IDp. When operating with in the mode the proxy will automatically acquire an access token (handling the refreshing or logins on your behalf) and tag outbound requests with a Authorization header. You can control which domains are tagged with the --forwarding-domains option. Note, this option use a **contains** comparison on domains. So, if you wanted to match all domains under *.svc.cluster.local can and simply use: --forwarding-domain=svc.cluster.local.

At present the service performs a login using oauth client_credentials grant type, so your IDp service must support direct (username/password) logins.

Example setup:

You have collection of micro-services which are permitted to speak to one another; you've already setup the credentials, roles, clients etc in Keycloak, providing granular role controls over issue tokens.

```YAML
- name: keycloak-proxy
  image: quay.io/gambol99/keycloak-proxy:latest
  args:
  - --enable-forwarding=true
  - --forwarding-username=projecta
  - --forwarding-password=some_password
  - --forwarding-domains=projecta.svc.cluster.local
  - --forwarding-domains=projectb.svc.cluster.local
  - --tls-ca-certificate=/etc/secrets/ca.pem
  - --tls-ca-key=/etc/secrets/ca-key.pem
  # Note: if you don't specify any forwarding domains, all domains will be signed; Also the code checks is the
  # domain 'contains' the value (it's not a regex) so if you wanted to sign all requests to svc.cluster.local, just use
  # svc.cluster.local
  volumeMounts:
  - name: keycloak-socket
    mountPoint: /var/run/keycloak
- name: projecta
  image: some_images

# test the forward proxy
$ curl -k --proxy http://127.0.0.1:3000 https://test.projesta.svc.cluster.local
```

Receiver side you could setup the keycloak-proxy (--no=redirects=true) and permit this proxy to verify and handle admission for you. Alternatively, the access token can found as a bearer token in the request.

#### **Forwarding Signing HTTPS Connect**

Handling HTTPS requires man in the middling the TLS connection. By default if no `--tls-ca-certificate` and `--tls-ca-key` is provided the proxy will use the default certificate. If you wish to verify the trust, you'll need to generate a CA, for example.

```shell
$ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.pem
$ bin/keycloak-proxy \
  --enable-forwarding \
  --forwarding-username=USERNAME \
  --forwarding-password=PASSWORD \
  --client-id=CLIENT_ID \
  --client-secret=SECRET \
  --discovery-url=https://keycloak.example.com/auth/realms/test \
  --tls-ca-certificate=ca.pem \
  --tls-ca-key=ca-key.pem
```

#### **HTTPS Redirect**

The proxy supports http listener, though the only real requirement for this would be perform http -> https redirect. You can enable the option via

```shell
--listen-http=127.0.0.1:80
--enable-security-filter=true  # is required for the https redirect
--enable-https-redirection
```

#### **Let's Encrypt**

Example of required configuration for Let's Encrypt support:

```YAML
listen: 0.0.0.0:443
enable-https-redirection: true
enable-security-filter: true
use-letsencrypt: true
letsencrypt-cache-dir: ./cache/
redirection-url: https://domain.tld:443/
hostnames:
  - domain.tld
```

Note: listening on the port 443 is mandatory requirement

#### **Access Token Encryption**

By default the session token *(i.e. access/id token)* is placed into a cookie in plaintext. If prefer you to encrypt the session cookie using --enable-encrypted-token and --encryption-key options. Note, the access token forwarded in the X-Auth-Token header to upstream is unaffected.

#### **Upstream Headers**

On protected resources the upstream endpoint will receive a number of headers added by the proxy, along with an custom claims.

```GO
# add the header to the upstream endpoint
id := user.(*userContext)
cx.Request().Header.Set("X-Auth-Email", id.email)
cx.Request().Header.Set("X-Auth-ExpiresIn", id.expiresAt.String())
cx.Request().Header.Set("X-Auth-Groups", strings.Join(id.groups, ","))
cx.Request().Header.Set("X-Auth-Roles", strings.Join(id.roles, ","))
cx.Request().Header.Set("X-Auth-Subject", id.id)
cx.Request().Header.Set("X-Auth-Token", id.token.Encode())
cx.Request().Header.Set("X-Auth-Userid", id.name)
cx.Request().Header.Set("X-Auth-Username", id.name)
// step: add the authorization header if requested
if r.config.EnableAuthorizationHeader {
	cx.Request().Header.Set("Authorization", fmt.Sprintf("Bearer %s", id.token.Encode()))
}
```

#### **Custom Claim Headers**

You can inject additional claims from the access token into the authorization headers via the --add-claims option. For example, a token from Keycloak provider might include the following claims.

```YAML
"resource_access": {},
"name": "Rohith Jayawardene",
"preferred_username": "rohith.jayawardene",
"given_name": "Rohith",
"family_name": "Jayawardene",
"email": "gambol99@gmail.com"
```

In order to request you receive the given_name, family_name and name in the authentication header we would add --add-claims=given_name --add-claims=family_name etc. Or in the configuration file

```YAML
add-claims:
- given_name
- family_name
- name
```

This would add the additional headers to the authenticated request along with standard ones.

```shell
X-Auth-Family-Name: Jayawardene
X-Auth-Given-Name: Rohith
X-Auth-Name: Rohith Jayawardene
```

#### **Encryption Key**

In order to remain stateless and not have to rely on a central cache to persist the 'refresh_tokens', the refresh token is encrypted and added as a cookie using *crypto/aes*. Naturally the key must be the same if your running behind a load balancer etc. The key length should either 16 or 32 bytes depending or whether you want AES-128 or AES-256.

#### **ClientID & Secret**

Note, the client secret is optional and only required for setups where the oauth provider is using access_type = confidential; if the provider is 'public' simple add the client id.
Alternatively, you might not need the proxy to perform the oauth authentication flow and instead simply verify the identity token (and potential role permissions), in which case, again
just drop the client secret and use the client id and discovery-url.

#### **Claim Matching**

The proxy supports adding a variable list of claim matches against the presented tokens for additional access control. So for example you can match the 'iss' or 'aud' to the token or custom attributes; note each of the matches are regex's. Examples,  --match-claims 'aud=sso.*' --claim iss=https://.*' or via the configuration file. Note, each of matches are regex's.

```YAML
match-claims:
  aud: openvpn
  iss: https://keycloak.example.com/auth/realms/commons
```

or via the CLI

```shell
--match-claims=auth=openvpn
--match-claims=iss=http://keycloak.example.com/realms/commons
```

Another example would be limiting the email domain permitted; say you have some  google apps domain with username@example.com and want to limit only to those users.


```YAML
match-claims:
  email: ^.*@example.com$
```

#### **Groups Claims**

You can match on the group claims within a token via the `groups` parameter available within the resource. Note while roles are implicitly required i.e. `roles=admin,user` the user MUST have roles 'admin' AND 'user', groups are applied with an OR operation, so `groups=users,testers` requires the user MUST be within 'users' OR 'testers'. At present the claim name is hardcoded to `groups` i.e a JWT token would look like the below.

```JSON
{
  "iss": "https://sso.example.com",
  "sub": "",
  "aud": "test",
  "exp": 1515269245,
  "iat": 1515182845,
  "email": "gambol99@gmail.com",
  "groups": [
    "group_one",
    "group_two"
  ],
  "name": "Rohith"
}
```

Note: I'm also considering changing the way groups are implemented, exchanging for how match-claims are done, such as `--match=[]groups=(a|b|c)` but would mean adding matches to URI resource first.

#### **Custom Pages**

By default the proxy will immediately redirect you for authentication and hand back 403 for access denied. Most users will probably want to present the user with a more friendly sign-in and access denied page. You can pass the command line options (or via config file) paths to the files i.e. --signin-page=PATH. The sign-in page will have a 'redirect' variable passed into the scope and holding the oauth redirection url. If you wish pass additional variables into the templates, perhaps title, sitename etc, you can use the --tags key=pair i.e. --tags title="This is my site"; the variable would be accessible from {{ .title }}

```HTML
<html>
<body>
<a href="{{ .redirect }}">Sign-in</a>
</body>
</html>
```

#### **White-listed URL's**

Depending on how the application url's are laid out, you might want protect the root / url but have exceptions on a list of paths, i.e. /health etc. Although you should probably fix this by fixing up the paths, you can add excepts to the protected resources.

```YAML
  resources:
  - uri: /some_white_listed_url
    white-listed: true
  - uri: /*
    methods:
      - GET
    roles:
      - <CLIENT_APP_NAME>:<ROLE_NAME>
      - <CLIENT_APP_NAME>:<ROLE_NAME>
```

Or on the command line

```shell
  --resources "uri=/some_white_listed_url|white-listed=true"
  --resources "uri=/*"  # requires authentication on the rest
  --resources "uri=/admin*|roles=admin,superuser|methods=POST,DELETE
```

#### **Mutual TLS**

The proxy support enforcing mutual TLS for the clients by simply adding the --tls-ca-certificate command line option or configuration file option. All clients connecting must present a certificate which was signed by the CA being used.

#### **Certificate Rotation**

The proxy will automatically rotate the server certificate's if the files change on disk. Note, no downtown will occur as the change is made inline. Client whom connected prior to the certificate rotation will be unaffected continue as normal with all new connections presented with the new certificate.

#### **Refresh Tokens**

Assuming a request for an access token contains a refresh token and the --enable-refresh-tokens is true, the proxy will automatically refresh the access token for you. The tokens themselves are kept either as an encrypted *(--encryption-key=KEY)* cookie *(cookie name: kc-state).* or a store *(still requires encryption key)*.

At present the only store supported are [Redis](https://github.com/antirez/redis) and [Boltdb](https://github.com/boltdb/bolt). To enable a local boltdb store. --store-url boltdb:///PATH or relative path boltdb://PATH. For redis the option is redis://[USER:PASSWORD@]HOST:PORT. In both cases the refresh token is encrypted before placing into the store.

#### **Logout Endpoint**

A */oauth/logout?redirect=url* is provided as a helper to logout the users. Aside from dropping any sessions cookies, we also attempt to revoke access via revocation url (config *revocation-url* or *--revocation-url*) with the provider. For Keycloak the url for this would be https://keycloak.example.com/auth/realms/REALM_NAME/protocol/openid-connect/logout, for Google https://accounts.google.com/o/oauth2/revoke. If the url is not specified we will attempt to grab the url from the OpenID discovery response.

#### **Cross Origin Resource Sharing (CORS)**

You can add CORS header via the --cors-[method] command line or configuration options.

 * Access-Control-Allow-Origin
 * Access-Control-Allow-Methods
 * Access-Control-Allow-Headers
 * Access-Control-Expose-Headers
 * Access-Control-Allow-Credentials
 * Access-Control-Max-Age

Either from the config file:

```YAML
cors-origins:
- '*'
cors-methods:
- GET
- POST
```

or via the command line arguments

```shell
--cors-origins [--cors-origins option]                  a set of origins to add to the CORS access control (Access-Control-Allow-Origin)
--cors-methods [--cors-methods option]                  the method permitted in the access control (Access-Control-Allow-Methods)
--cors-headers [--cors-headers option]                  a set of headers to add to the CORS access control (Access-Control-Allow-Headers)
--cors-exposes-headers [--cors-exposes-headers option]  set the expose cors headers access control (Access-Control-Expose-Headers)
```

#### **Upstream URL**

You can control the upstream endpoint via the --upstream-url option. Both http and https is supported with TLS verification and keepalive support configured via the --skip-upstream-tls-verify / --upstream-keepalives option. Note, the proxy can also upstream via a unix socket, --upstream-url unix://path/to/the/file.sock

#### **Endpoints**

* **/oauth/authorize** is authentication endpoint which will generate the OpenID redirect to the provider
* **/oauth/callback** is provider OpenID callback endpoint
* **/oauth/expired** is a helper endpoint to check if a access token has expired, 200 for ok and, 401 for no token and 401 for expired
* **/oauth/health** is the health checking endpoint for the proxy, you can also grab version from headers
* **/oauth/login** provides a relay endpoint to login via grant_type=password i.e. POST /oauth/login form values are username=USERNAME&password=PASSWORD (must be enabled)
* **/oauth/logout** provides a convenient endpoint to log the user out, it will always attempt to perform a back channel logout of offline tokens
* **/oauth/token** is a helper endpoint which will display the current access token for you
* **/oauth/metrics** is a prometheus metrics handler

#### **Metrics**

Assuming the *--enable-metrics* has been set, a Prometheus endpoint can be found on */oauth/metrics*; at present the only metric being exposed is a counter per http code.

### Limitations

Keep in mind [browser cookie limits](http://browsercookielimits.squawky.net/), if you use access or
refresh tokens in the browser cookie. Keycloak-proxy divides cookie automatically if your cookie
is longer than 4093 bytes. Real size of the cookie depends on the content of the issued access token.
Also, encryption might add additional bytes to the cookie size. If you have large cookies (>200 KB),
you might reach browser cookie limits.

All cookies are part of the header request, so you might find a problem with the max headers size
limits in your infrastructure (some load balancers have very low this value, such as 8 KB). Be
sure that all network devices have sufficient header size limits. Otherwise, your users won't be
able to obtain access token.

### **Contribution Guidelines**
----

#### **Pre-Development**
- Look for an existing Github issue describing the bug you have found/feature request you would like to see getting implemented.
- If no issue exists and there is reason to believe that your (non-trivial) contribution might be subject to an up-front design discussion, file an issue first and propose your idea.

#### **Development**
- Fork the repository.
- Create a feature branch (`git checkout -b my-new-feature master`).
- Commit your changes, preferring one commit per logical unit of work. Often times, this simply means having a single commit.
- If applicable, update the documentation in the [README file](README.md).
- In the vast majority of cases, you should add/amend a (regression) test for your bug fix/feature.
- Push your branch (`git push origin my-new-feature`).
- Create a new pull request.
- Address any comments your reviewer raises, pushing additional commits onto your branch along the way. In particular, refrain from amending/force-pushing until you receive an LGTM (Looks Good To Me) from your reviewer. This will allow for a better review experience.
