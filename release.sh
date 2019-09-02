#!/bin/bash -e
NAME="keycloak-gatekeeper"
PLATFORMS="darwin linux windows"
ARCHITECTURES="amd64"
GIT_SHA=$(git --no-pager describe --always --dirty)
BUILD_TIME=$(date '+%s')
LFLAGS="-X main.gitsha=$GIT_SHA -X main.compiled=$BUILD_TIME"

DIR="$PWD"
VERSION=`./get-version.sh`
echo "Version: $VERSION"

TMP=`mktemp -d`

# Perform some clean up before building it
clean() {
  rm -rf ./bin/* 2>/dev/null
  rm -rf ./release/* 2>/dev/null
}

release() {
  mkdir -p release
  for PLATFORM in $PLATFORMS; do
    EXT=""
    if [ "$PLATFORM" == "windows" ]; then
      EXT=".exe"
    fi
    for ARCH in $ARCHITECTURES; do
      env GOOS=$PLATFORM GOARCH=$ARCH CGO_ENABLED=0 go build -a -tags netgo -ldflags " -w $LFLAGS" -o bin/$NAME$EXT
      tar -czvf release/"$NAME-$PLATFORM-$ARCH".tar.gz -C bin/ $NAME$EXT >/dev/null
      sha1sum release/"$NAME-$PLATFORM-$ARCH".tar.gz | cut -d " " -f1 > release/"$NAME-$GOOS-$GOARCH".tar.gz.sha1
      # Test if tar file is not corrupted
      if ! tar -tf release/"$NAME-$PLATFORM-$ARCH".tar.gz &>/dev/null;then 
        echo "Corrupted tar file"
        exit 1
      fi
    done
  done
}

echo "------------------------------------------------------------------------------------------------------------"
echo "Building: $NAME-$VERSION"
echo ""

clean
release

echo "------------------------------------------------------------------------------------------------------------"
echo "Upload to jboss.org:"
echo ""

rsync -rv --protocol=28 $DIR/release/* keycloak@filemgmt.jboss.org:/downloads_htdocs/keycloak/$VERSION/gatekeeper/

echo "------------------------------------------------------------------------------------------------------------"
echo "Done"
echo "------------------------------------------------------------------------------------------------------------"
