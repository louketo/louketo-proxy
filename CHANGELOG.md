

#### **1.0.3 (April 30th, 2016)**

FIXES:
 * Fixes the cookie sessions expiraton

FEATURES:
 * Adding a idle duration configuration option which controls the expiration of access token cookie and thus session. 
   If the session is not used within that period, the session is removed. 
 * The upstream endpoint has also be a unix socket
 
BREAKING CHANGES:
 * Change the client id in json/yaml config file from clientid -> client-id
 
#### **1.0.2 (April 22th, 2016)**

FIXES:
 * Cleaned up a lot of code base to make this simplier
 * Fixed elements in the refresh tokens and simplified the controller
 * Removed of the code out from methods into functions to reduce the dependencies (unit testing is easier as well)
 * Fixed how the refresh tokens are implemented, i was somewhat confused between refresh token and offline token
 * Fixed the encryption key length, must be either 16 or 32 for aes-128/256 selection

FEATURES:
 * Added the ability to store the refresh token in either local boltdb file or a redis service rather than
   an encrypted cookie (note, the token regardless is encrypted)
 * Added a /oauth/logout endpoint to logout the user
 * Added a /oauth/login (niche requirement) to provide grant_type=password requests

TODO:
 * Really need to mock a oauth server to simplify the unit tests

BREAKING CHANGES:
 * Changed the following configuration options to conform to their command line equivalents
   - refresh_sessions -> refresh-sessions
   - discovery_url      -> discovery-url
   - redirection_url    -> redirection-url
   - tls_ca_certificate -> tls-ca-certificate
   - tls_private_key    -> tls-private-key
   - tls_cert           -> tls-cert
   - log_json_format    -> log-json-format
   - log_requests       -> log-requests
   - forbidden_page     -> forbidden-page
   - sign_in_page       -> sign-in-page
   - secret             -> client-secret

#### **1.0.1 (April 8th, 2016)**

FIXES:
 * Fixed the refresh tokens for those provides whom do not use JWT tokens, Google Connect for example

#### **1.0.0 (April 8th, 2016)**

FEATURES
 * Added the /oauth/expiration controller to test for access token expiration
 * Added the /oauth/token as a helper method to display the access token

FIXES:
 * Fixed and cleaned up a few niggling issues

#### **1.0.0-rc6 (March 31th, 2016)**

FIXES:
 * Added a option to control the upstream TLS verification
 * Added in the x-forwarded-for headers rather than overwriting
 * Moved back to using the official coreos go-oidc rather than the hacked version

#### **1.0.0-rc5 (March 15th, 2016)**

FEATURES:

 * Added the realm access roles for keycloak, beforehand the user contect
   was only parses roles which were from client applications

BUGS:

 * Fixed the gitlab-ci build scripts
 * Fixed the custom forbidden page bug
