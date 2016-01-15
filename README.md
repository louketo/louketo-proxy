[![Build Status](https://travis-ci.org/gambol99/keycloak-proxy.svg?branch=master)](https://travis-ci.org/gambol99/keycloak-proxy)
[![GoDoc](http://godoc.org/github.com/gambol99/keycloak-proxy?status.png)](http://godoc.org/github.com/gambol99/keycloak-proxy)

### **Keycloak Proxy**
----

Keycloak-proxy is a proxy service which at the risk of stating the obvious integrates with the [Keycloak](https://github.com/keycloak/keycloak) authentication service. 
The configuration and feature set is based on the actual java version of the [proxy](https://docs.jboss.org/keycloak/docs/1.1.0.Beta2/userguide/html/proxy.html). The service
supports both access tokens in browser cookie or bearer tokens.

```shell
[jest@starfury keycloak-proxy]$ bin/keycloak-proxy help
NAME:
   keycloak-proxy - is a proxy using the keycloak service for auth and authorization

USAGE:
   keycloak-proxy [global options] command [command options] [arguments...]
   
VERSION:
   v0.0.6, git+sha: 73e0db2
   
AUTHOR(S):
   Rohith <gambol99@gmail.com> 
   
COMMANDS:
   help, h	Shows a list of commands or help for one command
   
GLOBAL OPTIONS:
   --config 						the path to the configuration file for the keycloak proxy
   --listen "127.0.0.1:8080"				the interface the service should be listening on
   --secret 						the client secret used to authenticate to the oauth server
   --client-id 						the client id used to authenticate to the oauth serves
   --discovery-url 					the discovery url to retrieve the openid configuration
   --upstream-url "http://127.0.0.1:8080"		the url for the upstream endpoint you wish to proxy to
   --encryption-key 					the encryption key used to encrpytion the session state
   --redirection-url 					the redirection url, namely the site url, note: /oauth will be added to it
   --hostname [--hostname option --hostname option]	a list of hostname which the service will respond to, defaults to all
   --tls-cert 						the path to a certificate file used for TLS
   --tls-private-key 					the path to the private key for TLS support
   --scope [--scope option --scope option]		a variable list of scopes requested when authenticating the user
   --claim [--claim option --claim option]		a series of key pair values which must match the claims in the token present e.g. aud=myapp, iss=http://example.com etcd
   --resource [--resource option --resource option]	a list of resources 'uri=/admin|methods=GET|roles=role1,role2'
   --signin-page 					a custom template displayed for signin
   --forbidden-page 					a custom template used for access forbidden
   --tag [--tag option --tag option]			a keypair tag which is passed to the templates when render, i.e. title='My Page',site='my name' etc
   --max-session "1h0m0s"				if refresh sessions are enabled we can limit their duration via this
   --skip-token-verification				testing purposes ONLY, the option allows you to bypass the token verification, expiration and roles are still enforced
   --proxy-protocol					switches on proxy protocol support on the listen (not supported yet)
   --refresh-sessions					enables the refreshing of tokens via offline access
   --json-logging					switch on json logging rather than text (defaults true)
   --log-requests					switch on logging of all incoming requests (defaults true)
   --verbose						switch on debug / verbose logging
   --help, -h						show help
   --version, -v					print the version
```

#### **Configuration**

The configuration can come from a yaml/json file and or the command line options (note, command options have a higher priority and will override any options referenced in a config file)

```YAML


# is the url for retrieve the openid configuration - normally the <server>/auth/realm/<realm_name>
discovery_url: https://keycloak.example.com/auth/realms/<REALM_NAME>
# the client id for the 'client' application
clientid: <CLIENT_ID>
# the secret associated to the 'client' application
secret: <CLIENT_SECRET>
# the interface definition you wish the proxy to listen, all interfaces is specified as ':<port>'
listen: 127.0.0.1:3000
# whether to request offline access and use a refresh token
refresh_session: true
# assuming you are using refresh tokens, specify the maximum amount of time the refresh token can last
max_session: 1h
# the location of a certificate you wish the proxy to use for TLS support
tls_cert:
# the location of a private key for TLS
tls_private_key:
# the redirection url, essentially the site url, note: /oauth/callback is added at the end
redirection_url: http://127.0.0.3000
# the encryption key used to encode the session state
encryption_key: <ENCRYPTION_KEY>
# the upstream endpoint which we should proxy request
upstream: http://127.0.0.1:80
# additional scopes to add to add to the default (openid+email+profile)
scopes:
  - vpn-user

# a collection of resource i.e. urls that you wish to protect
resources:
  - url: /admin/test
    # the methods on this url that should be protected, if missing, we assuming all
    methods:
      - GET
    # a list of roles the user must have in order to accces urls under the above
    roles_allowed:
      - openvpn:vpn-user
      - openvpn:prod-vpn
      - test
  - url: /admin
    methods:
      - GET
    roles_allowed:
      - openvpn:vpn-user
      - openvpn:commons-prod-vpn
```


#### **Example Usage**

Assuming you have some web service you wish protected by Keycloak;

a) Create the *client* under the Keycloak GUI or CLI; the client protocol is *'openid-connect'*, access-type:  *confidential*.
b) Add a Valid Redirect URIs of *http://127.0.0.1:3000/oauth/callback*.
c) Grab the client id and client secret.
d) Create the various roles under the client or existing clients for authorization purposes.

**The default config**

```YAML
discovery_url: https://keycloak.example.com/auth/realms/<REALM_NAME>
clientid: <CLIENT_ID>
secret: <CLIENT_SECRET>
listen: 127.0.0.1:3000
redirection_url: http://127.0.0.3000
refresh_session: false
encryption_key: AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j
upstream: http://127.0.0.1:80

resources:
  - url: /admin
    methods:
      - GET
    roles_allowed:
      - <CLIENT_APP_NAME>:<ROLE_NAME>
      - <CLIENT_APP_NAME>:<ROLE_NAME>
```

#### **Upstream Headers**

On protected resources the upstream endpoint will receive a number of headers added by the proxy;

```GO
# add the header to the upstream endpoint
cx.Request.Header.Add("X-Auth-UserId", id.id)
cx.Request.Header.Add("X-Auth-Subject", id.preferredName)
cx.Request.Header.Add("X-Auth-Username", id.name)
cx.Request.Header.Add("X-Auth-Email", id.email)
cx.Request.Header.Add("X-Auth-ExpiresIn", id.expiresAt.String())
cx.Request.Header.Add("X-Auth-Token", id.token.Encode())
cx.Request.Header.Add("X-Auth-Roles", strings.Join(id.roles, ","))

# plus the default
cx.Request.Header.Add("X-Forwarded-For", <CLIENT_IP>)
cx.Request.Header.Add("X-Forwarded-Proto", <CLIENT_PROTO>)
```

#### **Encryption Key**

In order to remain stateless and not have to rely on a central cache to persist the 'refresh_tokens', the refresh token is encrypted and added as a cookie using *crypto/aes*. Naturally the key must be the same if your running behind a load balancer etc.  

#### **Claim Matching**

Note, you can add a variable list of claim matches on the presented token by using the --claim 'key=pair' command option or a map 'claims' in the config file (see the example file), before permitting
access via the proxy each of the claims inside the token are evaluated.

#### **Custom Pages**

By default the proxy will immediately redirect you for authentication and hand back 403 for access denied. Most users will probably want to present the user with a more friendly
sign-in and access denied page. You can pass the command line options (or via config file) paths to the files i.e. --signin-pag=PATH. The sign-in page will have a 'redirect' 
passed into the scope hold the oauth redirection url. If you wish pass additional variables into the templates, perhaps title, sitename etc, you can use the --tag key=pair i.e. 
--tag title="This is my site"; the variable would be accessible from {{ .title }}

```HTML
<html>
<body>
<a href="{{ .redirect }}">Sign-in</a>
</body>
</html>


```