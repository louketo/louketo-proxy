
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
