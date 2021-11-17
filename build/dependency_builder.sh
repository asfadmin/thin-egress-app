#!/usr/bin/env bash

# required env vars:
# WORKSPACE - will contain the thin-egress-app project
# DEPENDENCYLAYERFILENAME - this script will output a zip file with this name

echo "RUNNING dependency_builder.sh"

echo "inside dependency building container env:"
printenv

RUN yum install -y amazon-linux-extras && \
    amazon-linux-extras enable python3.8 && \
    yum install -y zip python38 python38-pip && \\

RUN python3.8 -m pip install --upgrade pip && \

mkdir -p /tmp/pkg/python


cd /tmp/pkg/python || exit

echo "Updating Pip..."
python3.8 -m pip install -U pip
echo "Installing setuptools..."
python3.8 -m pip install --upgrade setuptools
echo "Installing ${WORKSPACE}/rain-api-core/requirements.txt"
python3.8 -m pip install -r "${WORKSPACE}"/rain-api-core/requirements.txt --target .
echo "Installing ${WORKSPACE}/lambda/requirements.txt"
python3.8 -m pip install -r "${WORKSPACE}"/lambda/requirements.txt --target .
python3.8 -m pip install cffi
echo "Current version of Python" # TODO: Remove
python3.8 --version

# get rid of unneeded things to make code zip smaller
rm -rf ./*.dist-info
# rm -rf pip # commented out because https://snyk.io/vuln/SNYK-PYTHON-PIP-609855
rm -rf docutils
rm -rf chalice/cli # cli in lambda? No way!
rm -rf botocore # included with lambda, just takes up space here
rm -rf setuptools
rm -rf tests
rm -rf easy_install.py
rm -f typing.py # MUST be removed, its presence causes error every time

cd ..
# now in pkg/
echo "zipping dependencies to ${WORKSPACE}/${DEPENDENCYLAYERFILENAME}."

ls -lah

zip -r9 "${WORKSPACE}/${DEPENDENCYLAYERFILENAME}" .

echo "all done making dependency layer"
