#!/usr/bin/env bash

# required env vars:
# WORKSPACE - will contain the thin-egress-app project
# DEPENDENCYLAYERFILENAME - this script will output a zip file with this name

echo "RUNNING dependency_builder.sh"

echo "inside dependency building container env:"
printenv

yum install -y amazon-linux-extras && \
amazon-linux-extras enable python3.8

yum install -y zip git python38 python38-pip
yum clean all

mkdir -p /tmp/pkg/python


cd /tmp/pkg/python || exit

echo "Updating Pip..."
python3.8 -m pip install -U pip
echo "Installing setuptools..."
python3.8 -m pip install --upgrade setuptools
echo "Installing ${WORKSPACE}/requirements.txt"
python3.8 -m pip install -r "${WORKSPACE}"/requirements.txt --target .

# get rid of unneeded things to make code zip smaller
rm -rf ./*.dist-info
rm -rf docutils
rm -rf click chalice/cli # cli in lambda? No way!
rm -rf botocore # included with lambda, just takes up space here
rm -rf pip setuptools wheel easy_install.py
rm -rf tests

cd ..
# now in pkg/
echo "zipping dependencies to ${WORKSPACE}/${DEPENDENCYLAYERFILENAME}."

ls -lah

zip -r9 "${WORKSPACE}/${DEPENDENCYLAYERFILENAME}" .

echo "all done making dependency layer"
