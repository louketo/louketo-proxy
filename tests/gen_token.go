/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"
	"time"

	"github.com/codegangsta/cli"
	"github.com/coreos/go-oidc/jose"
	"fmt"
	"strings"
)

func main() {
	app := cli.NewApp()
	app.Version = "v0.0.1"
	app.Author = "Rohith Jayawardene"
	app.Email = "gambol99@gmail.com"
	app.Flags = []cli.Flag {
		cli.StringFlag{
			Name:	"issuer",
			Usage: 	"the issuer of the token when generate",
			Value:  "http://keycloak.example.com/auth/realms/test",
		},
		cli.StringFlag{
			Name:	"audience",
			Usage:  "the audience of the token is directed to",
			Value:  "test",
		},
		cli.StringSliceFlag{
			Name:   "realm-role",
			Usage:  "a list of roles the token includes from the realm",
		},
		cli.StringSliceFlag{
			Name:   "role",
			Usage:  "a list of client roles the role includes, i.e. NAME:ROLE",
		},
		cli.DurationFlag{
			Name:   "expiration",
			Usage:  "the time from now the token should expire",
			Value:  time.Duration(1) * time.Hour,
		},
		cli.StringSliceFlag{
			Name:   "claims",
			Usage:  "a series of keypair claims which should be added to the token",
		},
	}
	app.Action = func(cx *cli.Context) {

		header := jose.JOSEHeader{
			"alg": "RS256",
		}

		claims := jose.Claims{
			"exp":		time.Now().Add(cx.Duration("expiration")).Unix(),
			"iat":          "1450372669",
			"iss":          cx.String("issuer"),
			"aud":          cx.String("audience"),
			"sub":          cx.String("subject"),
		}
		// step: add the realm roles if any
		if len(cx.StringSlice("realm-role")) {
			claims["realm_access"] = map[string]interface{}{"roles":[]string{}}
			for _, x := range cx.StringSlice("realm-roles") {
				claims["realm_access"]["roles"] = append(claims["realm_access"]["roles"], x)
			}
		}
		// step: add the roles if any
		if len(cx.StringSlice("role")) {
			claims["resource_access"] = map[string]interface{}{}
			for _, k := range cx.StringSlice("roles") {
				elements := strings.Split(k, ":")
				if len(elements) {

				}
				roles, found := claims["resource_access"][elements[0]]
				if !found {
					claims["resource_access"][elements[0]] = map[string]interface{}{
						"roles": []string{},
					}
					roles = claims["resource_access"][elements[0]]
				}
				for _, x := range cx.StringSlice("role") {
					roles["roles"] = append(roles["roles"], x)
				}
			}
		}
		// step: add the custom claims
		for k, v := range cx.StringSlice("claim") {


		}

		// step: create the token
		token, err := jose.NewJWT(header, claims)
		if err != nil {

		}

		// step: sign the token
		signer, err :=jose.NewSignerRSA()
		if err != nil {


		}

		signer.Sign(token.Encode())


		fmt.Fprintf(os.Stdout, token.Encode() + "\n")
	}

	app.Run(os.Args)
}


