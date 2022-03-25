#!/usr/bin/env bash

# exit when any command fails
set -e

WORKSPACE=$(pwd)
OUT_FILE=$1
BUILD_DIR="$WORKSPACE/$2"
REQUIREMENTS_FILE="${WORKSPACE}/requirements/requirements.txt"

mkdir -p $BUILD_DIR/python
cd $BUILD_DIR/python || exit

echo "Installing ${REQUIREMENTS_FILE}"
python3.8 -m pip install \
  --upgrade \
  -r "$REQUIREMENTS_FILE" \
  --target $BUILD_DIR/python \
  --cache-dir $BUILD_DIR/.pip-cache/

# get rid of unneeded things to make code zip smaller
rm -rf ./*.dist-info
rm -rf docutils
rm -rf click chalice/cli # cli in lambda? No way!
rm -rf botocore # included with lambda, just takes up space here
rm -rf pip setuptools wheel easy_install.py
rm -rf tests

cd $BUILD_DIR
echo "Zipping dependencies to ${WORKSPACE}/${OUT_FILE}"

zip -r9 -q "${WORKSPACE}/${OUT_FILE}" python

echo "Done making dependency layer"
