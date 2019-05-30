#!/bin/sh

docker run \
  --rm \
  --mount type=bind,source="$(pwd)",target=/source \
  python:3-alpine \
  /source/bin/docker-build.sh
