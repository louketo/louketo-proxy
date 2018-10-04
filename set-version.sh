#!/bin/bash -e

NEW_VERSION=$1

CURRENT=`awk '/release.*=/ { print $3 }' doc.go | sed 's/"//g'`
sed -i "s/$CURRENT/$NEW_VERSION/g" doc.go 
