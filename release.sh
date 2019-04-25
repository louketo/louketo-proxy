#!/bin/bash -e

DIR="$PWD"
VERSION=`./get-version.sh`
echo "Version: $VERSION"

TMP=`mktemp -d`

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
