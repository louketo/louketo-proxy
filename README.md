### **Keycloak Proxy**
----

Keycloak-proxy is a proxy service which at the risk of stating the obvious integrates with the [Keycloak](https://github.com/keycloak/keycloak) authentication service. The configuration and feature set is based on the actual java version of the [proxy](https://docs.jboss.org/keycloak/docs/1.1.0.Beta2/userguide/html/proxy.html). The 

```shell
[jest@starfury keycloak-proxy]$ bin/keycloak-proxy --help
Usage of bin/keycloak-proxy:
  -alsologtostderr         log to standard error as well as files
  -config string           the path to the configuration file for the keycloak proxy service, in yaml or json format
  -httptest.serve string   if non-empty, httptest.NewServer serves on this address and blocks
  -log_backtrace_at value  when logging hits line file:N, emit a stack trace (default :0)
  -log_dir string          If non-empty, write log files in this directory
  -logtostderr             log to standard error instead of files
  -stderrthreshold value   logs at or above this threshold go to stderr
  -v value                 log level for V logs
  -vmodule value           comma-separated list of pattern=N settings for file-filtered logging
```

#### **Configuration**

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
Below is a sample kubeconfig file with two contexts for dev and prod clusters, the file is placed / located at ~/.kube/config by default. You can find a cheat-sheet for the kubectl command [here](https://github.com/kubernetes/kubernetes/blob/master/docs/user-guide/kubectl-cheatsheet.md)

#### **Upstream Headers**

On protected resources the upstream endpoint will receive a number of headers added by the proxy;

```GO
cx.Request.Header.Add("KEYCLOAK_SUBJECT", id.preferredName)
cx.Request.Header.Add("KEYCLOAK_USERNAME", id.name)
cx.Request.Header.Add("KEYCLOAK_EMAIL", id.email)
cx.Request.Header.Add("KEYCLOAK_EXPIRES_IN", id.expiresAt.String())
cx.Request.Header.Add("KEYCLOAK_ACCESS_TOKEN", id.token.Encode())
cx.Request.Header.Add("KEYCLOAK_ROLES", strings.Join(id.roles, ","))

# plus the default
cx.Request.Header.Add("X-Forwarded-For", <CLIENT_IP>)
cx.Request.Header.Add("X-Forwarded-Proto", <CLIENT_PROTO>)
```

#### **Encryption Key**

In order to remain stateless and not have to rely on a central cache to persist the 'refresh_tokens', the refresh token is encrypted and added as a cookie using *crypto/aes*. Naturally the key must be the same if your running behind a load balancer etc.  
