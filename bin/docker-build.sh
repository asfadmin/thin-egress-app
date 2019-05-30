#!/bin/sh

set -e

CODE_ARCHIVE_FILENAME=/source/pkg/thin-egress-app-code.zip

mkdir -p /source/pkg
rm -f "$CODE_ARCHIVE_FILENAME"

apk --no-cache add zip

mkdir /pkg
(
  set -e
  cd /pkg
  pip3 install -r /source/lambda/requirements.txt  --target .
  zip -r9 "$CODE_ARCHIVE_FILENAME" ./*
)

(
  set -e
  cd /source/lambda
  zip -g "$CODE_ARCHIVE_FILENAME" ./*.py
  zip -g -r "$CODE_ARCHIVE_FILENAME" ./templates
)
