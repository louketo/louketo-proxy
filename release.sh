#!/bin/bash -e

DIR="$PWD"
VERSION=`./get-version.sh`
echo "Version: $VERSION"

TMP=`mktemp -d`
export GOPATH=$TMP/go

mkdir -p $GOPATH/src/github.com/keycloak
ln -s $DIR $GOPATH/src/github.com/keycloak/keycloak-gatekeeper
cd $GOPATH/src/github.com/keycloak/keycloak-gatekeeper

echo "------------------------------------------------------------------------------------------------------------"
echo "Building:"
echo ""

make release


echo "------------------------------------------------------------------------------------------------------------"
echo "Upload to jboss.org:"
echo ""

rsync -rv --protocol=28 $DIR/release/* keycloak@filemgmt.jboss.org:/downloads_htdocs/keycloak/$VERSION/gatekeeper/


echo "------------------------------------------------------------------------------------------------------------"
echo "Done"
echo "------------------------------------------------------------------------------------------------------------"
