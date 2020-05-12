# Louketo Proxy

Louketo is a proxy which integrates with OpenID Connect (OIDC) Providers, it supports both access tokens in a browser cookie or bearer tokens.

This documentation details how to build and configure Louketo followed by details of how to use each of its features.

For further information, see the included help file which includes a
full list of commands and switches. View the file by entering the
following at the command line (modify the location to match where you
install Louketo Proxy):

``` bash
    $ bin/louketo-proxy help
```
## Requirements
    
  - Go 1.13 or higher
  - Make

## Configuration options

Configuration can come from a YAML/JSON file or by using command line
options. Here is a list of options.

``` yaml
# is the URL for retrieve the OpenID configuration
discovery-url: <DISCOVERY URL>
# the client id for the 'client' application
client-id: <CLIENT_ID>
# the secret associated to the 'client' application
client-secret: <CLIENT_SECRET>
# the interface definition you wish the proxy to listen, all interfaces is specified as ':<port>', unix sockets as unix://<REL_PATH>|</ABS PATH>
listen: :3000
# whether to enable refresh tokens
enable-refresh-tokens: true
# the location of a certificate you wish the proxy to use for TLS support
tls-cert:
# the location of a private key for TLS
tls-private-key:
# the redirection URL, essentially the site URL, note: /oauth/callback is added at the end
redirection-url: http://127.0.0.1:3000
# the encryption key used to encode the session state
encryption-key: <ENCRYPTION_KEY>
# the upstream endpoint which we should proxy request
upstream-url: http://127.0.0.1:80
# Returns HTTP 401 when no authentication is present, used with forward proxies.
no-redirects: false 
# additional scopes to add to the default (openid+email+profile)
scopes:
- vpn-user
# a collection of resource i.e. URLs that you wish to protect
resources:
- uri: /admin/test
  # the methods on this URL that should be protected, if missing, we assuming all
  methods:
  - GET
  # a list of roles the user must have in order to access URLs under the above
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

Options issued at the command line have a higher priority and will
override or merge with options referenced in a config file. Examples of
each style are shown in the following sections.

## Example of usage and configuration with Keycloak

Assuming you have some web service you wish protected by
Keycloak:

  - Create the **client** using the Keycloak GUI or CLI; the
    client protocol is **'openid-connect'**, access-type:
    **confidential**.

  - Add a Valid Redirect URI of
    **<http://127.0.0.1:3000/oauth/callback>**.

  - Grab the client id and client secret.

  - Create the roles under the client or existing clients for
    authorization purposes.

Here is an example configuration file.

``` yaml
client-id: <CLIENT_ID>
client-secret: <CLIENT_SECRET> # require for access_type: confidential
# Note the redirection-url is optional, it will default to the X-Forwarded-Proto / X-Forwarded-Host r the URL scheme and host not found
discovery-url: https://keycloak.example.com/auth/realms/<REALM_NAME>
# Indicates we should deny by default all requests and explicitly specify what is permitted
enable-default-deny: true
encryption-key: AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j
listen: :3000
redirection-url: http://127.0.0.1:3000
upstream-url: http://127.0.0.1:80
resources:
- uri: /admin*
  methods:
  - GET
  roles:
  - client:test1
  - client:test2
  require-any-role: true
  groups:
  - admins
  - users
- uri: /backend*
  roles:
  - client:test1
- uri: /public/*
# Allow access to the resource above 
  white-listed: true
- uri: /favicon
# Allow access to the resource above 
  white-listed: true
- uri: /css/*
# Allow access to the resource above 
  white-listed: true
- uri: /img/*
# Allow access to the resource above 
  white-listed: true
# Adds custom headers
headers:
  myheader1: value_1
  myheader2: value_2
```

Anything defined in a configuration file can also be configured using
command line options, such as in this example.

``` bash
bin/louketo-proxy \
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
    --resources="uri=/public/*|white-listed=true" \
    --headers="myheader1=value1" \
    --headers="myheader2=value2"
```

By default, the roles defined on a resource perform a logical `AND` so
all roles specified must be present in the claims, this behavior can be
altered by the `require-any-role` option, however, so as long as one
role is present the permission is granted.

## OpenID Provider Communication

By default the communication with the OpenID provider is direct. If you
wish, you can specify a forwarding proxy server in your configuration
file:

``` yaml
openid-provider-proxy: http://proxy.example.com:8080
```

## HTTP routing

By default, all requests will be proxied on to the upstream, if you wish
to ensure all requests are authenticated you can use this:

``` bash
--resource=uri=/* # note, unless specified the method is assumed to be 'any|ANY'
```

The HTTP routing rules follow the guidelines from
[chi](https://github.com/go-chi/chi#router-design). The ordering of the
resources does not matter, the router will handle that for you.

## Session-only cookies

By default, the access and refresh cookies are session-only and disposed
of on browser close; you can disable this feature using the
`--enable-session-cookies` option.

## Forward-signing proxy

Forward-signing provides a mechanism for authentication and
authorization between services using tokens issued from the IdP. When
operating in this mode the proxy will automatically acquire an access
token (handling the refreshing or logins on your behalf) and tag
outbound requests with an Authorization header. You can control which
domains are tagged with the `--forwarding-domains` option. Note, this
option uses a **contains** comparison on domains. So, if you wanted to
match all domains under \*.svc.cluster.local you can use:
`--forwarding-domain=svc.cluster.local`.

At present, the service performs a login using OAuth *client\_credentials*
grant type, so your IdP service must support direct (username/password)
logins.

Example setup:

You have a collection of micro-services which are permitted to speak to
one another; you have already set up the credentials, roles, and clients
in Keycloak, providing granular role controls over issue tokens.

``` yaml
- name: louketo-proxy
  image: quay.io/louketo/louketo-proxy:latest
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

On the receiver side, you could set up the Louketo Proxy
`--no-redirects=true` and permit this to verify and handle admission for
you. Alternatively, the access token can found as a bearer token in the
request.

## Forwarding signed HTTPS connections

Handling HTTPS requires a man-in-the-middle sort of TLS connection. By
default, if no `--tls-ca-certificate` and `--tls-ca-key` are provided
the proxy will use the default certificate. If you wish to verify the
trust, you’ll need to generate a CA, for example.

``` bash
$ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.pem
$ bin/louketo-proxy \
  --enable-forwarding \
  --forwarding-username=USERNAME \
  --forwarding-password=PASSWORD \
  --client-id=CLIENT_ID \
  --client-secret=SECRET \
  --discovery-url=https://keycloak.example.com/auth/realms/test \
  --tls-ca-certificate=ca.pem \
  --tls-ca-key=ca-key.pem
```

## HTTPS redirect

The proxy supports an HTTP listener, so the only real requirement here
is to perform an HTTP → HTTPS redirect. You can enable the option like
this:

``` bash
--listen-http=127.0.0.1:80
--enable-security-filter=true  # is required for the https redirect
--enable-https-redirection
```

## Let’s Encrypt configuration

Here is an example of the required configuration for Let’s Encrypt
support:

``` yaml
listen: 0.0.0.0:443
enable-https-redirection: true
enable-security-filter: true
use-letsencrypt: true
letsencrypt-cache-dir: ./cache/
redirection-url: https://domain.tld:443/
hostnames:
  - domain.tld
```

Listening on port 443 is mandatory.

## Access token encryption

By default, the session token is placed into a cookie in plaintext. If
you prefer to encrypt the session cookie, use the
`--enable-encrypted-token` and `--encryption-key` options. Note that the
access token forwarded in the X-Auth-Token header to upstream is
unaffected.

## Upstream headers

On protected resources, the upstream endpoint will receive a number of
headers added by the proxy, along with custom claims, like this:

- X-Auth-Email
- X-Auth-ExpiresIn
- X-Auth-Groups
- X-Auth-Roles
- X-Auth-Subject
- X-Auth-Token
- X-Auth-Userid
- X-Auth-Username

To control the `Authorization` header use the
`enable-authorization-header` YAML configuration or the
`--enable-authorization-header` command line option. By default, this
option is set to `true`.

## Custom claim headers

You can inject additional claims from the access token into the
upstream headers with the `--add-claims` option. For example, a
token from a Keycloak provider might include the following
claims:

``` yaml
"resource_access": {},
"name": "Beloved User",
"preferred_username": "beloved.user",
"given_name": "Beloved",
"family_name": "User",
"email": "beloved@example.com"
```

In order to request you receive the *given\_name*, *family\_name*, and name
in the authentication header, we would add `--add-claims=given_name` and
`--add-claims=family_name` and so on, or we can do it in the
configuration file, like this:

``` yaml
add-claims:
- given_name
- family_name
- name
```

This would add the additional headers to the authenticated request along
with standard ones.

``` bash
X-Auth-Family-Name: User
X-Auth-Given-Name: Beloved
X-Auth-Name: Beloved User
```

## Custom headers

You can inject custom headers using the `--headers="name=value"` option
or the configuration file:

    headers:
      name: value

## Encryption key

In order to remain stateless and not have to rely on a central cache to
persist the *refresh\_tokens*, the refresh token is encrypted and added as
a cookie using **crypto/aes**. The key must be the same if you are
running behind a load balancer. The key length should be either *16* or *32*
bytes, depending or whether you want *AES-128* or *AES-256*.

## Claim matching

The proxy supports adding a variable list of claim matches against the
presented tokens for additional access control. You can match the 'iss'
or 'aud' to the token or custom attributes; each of the matches are
regexes. For example, `--match-claims 'aud=sso.*'` or `--claim
iss=https://.*'` or via the configuration file, like this:

``` yaml
match-claims:
  aud: openvpn
  iss: https://keycloak.example.com/auth/realms/commons
```

or via the CLI, like this:

``` bash
--match-claims=auth=openvpn
--match-claims=iss=http://keycloak.example.com/realms/commons
```

You can limit the email domain permitted; for example, if you want to
limit to only users on the example.com domain:

``` yaml
match-claims:
  email: ^.*@example.com$
```

The adapter supports matching on multi-value strings claims. The match
will succeed if one of the values matches, for example:

``` yaml
match-claims:
  perms: perm1
```

will successfully match

``` json
{
  "iss": "https://sso.example.com",
  "sub": "",
  "perms": ["perm1", "perm2"]
}
```

## Group claims

You can match on the group claims within a token via the `groups`
parameter available within the resource. While roles are implicitly
required, such as `roles=admin,user` where the user MUST have roles
'admin' AND 'user', groups are applied with an OR operation, so
`groups=users,testers` requires that the user MUST be within either
'users' OR 'testers'. The claim name is hard-coded to `groups`, so a *JWT*
token would look like this:

``` json
{
  "iss": "https://sso.example.com",
  "sub": "",
  "aud": "test",
  "exp": 1515269245,
  "iat": 1515182845,
  "email": "beloved@example.com",
  "groups": [
    "group_one",
    "group_two"
  ],
  "name": "Beloved"
}
```

## Custom pages

By default, Louketo Proxy will immediately redirect you
for authentication and hand back a 403 for access denied. Most users
will probably want to present the user with a more friendly sign-in and
access denied page. You can pass the command line options (or via config
file) paths to the files with `--signin-page=PATH`. The sign-in page
will have a 'redirect' variable passed into the scope and holding the
OAuth redirection URL. If you wish to pass additional variables into the
templates, such as title, sitename and so on, you can use the -`-tags
key=pair` option, like this: `--tags title="This is my site"` and the
variable would be accessible from `{{ .title }}`.

``` html
<html>
<body>
<a href="{{ .redirect }}">Sign-in</a>
</body>
</html>
```

## White-listed URL’s

Depending on how the application URL’s are laid out, you might want
protect the root / URL but have exceptions on a list of paths, for
example `/health`. While this is best solved by adjusting the paths, you
can add exceptions to the protected resources, like this:

``` yaml
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

``` bash
  --resources "uri=/some_white_listed_url|white-listed=true"
  --resources "uri=/*"  # requires authentication on the rest
  --resources "uri=/admin*|roles=admin,superuser|methods=POST,DELETE"
```

## Mutual TLS

The proxy support enforcing mutual TLS for the clients by adding the
`--tls-ca-certificate` command line option or configuration file option.
All clients connecting must present a certificate that was signed by
the CA being used.

## Certificate rotation

The proxy will automatically rotate the server certificates if the files
change on disk. Note, no downtime will occur as the change is made
inline. Clients who connected before the certificate rotation will be
unaffected and will continue as normal with all new connections
presented with the new certificate.

## Refresh tokens

If a request for an access token contains a refresh token and
`--enable-refresh-tokens` is set to `true`, the proxy will automatically
refresh the access token for you. The tokens themselves are kept either
as an encrypted (`--encryption-key=KEY`) cookie **(cookie name:
kc-state).** or a store **(still requires encryption key)**.

At present the only store options supported are
[Redis](https://github.com/antirez/redis) and
[Boltdb](https://github.com/boltdb/bolt).

To enable a local BoltDB store use `--store-url boltdb:///PATH` or using
a relative path `boltdb://PATH`.

To enable a local Redis store use `redis://[USER:PASSWORD@]HOST:PORT`.
In both cases, the refresh token is encrypted before being placed into
the store.

## Logout endpoint

A **/oauth/logout?redirect=url** is provided as a helper to log users
out. In addition to dropping any session cookies, we also attempt to
revoke access via revocation URL (config **revocation-url** or
**--revocation-url**) with the provider. For Keycloak, the URL for this
would be
<https://keycloak.example.com/auth/realms/REALM_NAME/protocol/openid-connect/logout>.
If the URL is not specified we will attempt to grab the URL from the
OpenID discovery response.

## Cross-origin resource sharing (CORS)

You can add a CORS header via the `--cors-[method]` with these
configuration options.

  - Access-Control-Allow-Origin

  - Access-Control-Allow-Methods

  - Access-Control-Allow-Headers

  - Access-Control-Expose-Headers

  - Access-Control-Allow-Credentials

  - Access-Control-Max-Age

You can add using the config file:

``` yaml
cors-origins:
- '*'
cors-methods:
- GET
- POST
```

or via the command line:

``` bash
--cors-origins [--cors-origins option]                  a set of origins to add to the CORS access control (Access-Control-Allow-Origin)
--cors-methods [--cors-methods option]                  the method permitted in the access control (Access-Control-Allow-Methods)
--cors-headers [--cors-headers option]                  a set of headers to add to the CORS access control (Access-Control-Allow-Headers)
--cors-exposes-headers [--cors-exposes-headers option]  set the expose cors headers access control (Access-Control-Expose-Headers)
```

## Upstream URL

You can control the upstream endpoint via the `--upstream-url` option.
Both HTTP and HTTPS are supported with TLS verification and keep-alive
support configured via the `--skip-upstream-tls-verify` /
`--upstream-keepalives` option. Note, the proxy can also upstream via a
UNIX socket, `--upstream-url unix://path/to/the/file.sock`.

## Endpoints

  - **/oauth/authorize** is authentication endpoint which will generate
    the OpenID redirect to the provider

  - **/oauth/callback** is provider OpenID callback endpoint

  - **/oauth/expired** is a helper endpoint to check if a access token
    has expired, 200 for ok and, 401 for no token and 401 for expired

  - **/oauth/health** is the health checking endpoint for the proxy, you
    can also grab version from headers

  - **/oauth/login** provides a relay endpoint to login via
    `grant_type=password`, for example, `POST /oauth/login` form values
    are `username=USERNAME&password=PASSWORD` (must be enabled)

  - **/oauth/logout** provides a convenient endpoint to log the user
    out, it will always attempt to perform a back channel log out of
    offline tokens

  - **/oauth/token** is a helper endpoint which will display the current
    access token for you

  - **/oauth/metrics** is a Prometheus metrics handler

## Metrics

Assuming `--enable-metrics` has been set, a Prometheus endpoint can be
found on **/oauth/metrics**; at present the only metric being exposed is
a counter per HTTP code.

## Limitations

Keep in mind [browser cookie
limits](http://browsercookielimits.squawky.net/) if you use access or
refresh tokens in the browser cookie. Louketo Proxy divides
the cookie automatically if your cookie is longer than 4093 bytes. The real
size of the cookie depends on the content of the issued access token.
Also, encryption might add additional bytes to the cookie size. If you
have large cookies (\>200 KB), you might reach browser cookie limits.

All cookies are part of the header request, so you might find a problem
with the max headers size limits in your infrastructure (some load
balancers have very low this value, such as 8 KB). Be sure that all
network devices have sufficient header size limits. Otherwise, your
users won’t be able to obtain an access token.

## Known Issues

There is a known issue with the Keycloak server 4.6.0.Final in which
Louketo Proxy is unable to find the *client\_id* in the *aud* claim. This
is due to the fact the *client\_id* is not in the audience anymore. The
workaround is to add the "Audience" protocol mapper to the client with
the audience pointed to the *client\_id*. For more information, see
[KEYCLOAK-8954](https://issues.redhat.com/browse/KEYCLOAK-8954).
