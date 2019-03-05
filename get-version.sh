#!/bin/bash -e

awk '/release.*=/ { print $3 }' doc.go | sed 's/"//g'
