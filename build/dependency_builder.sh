#!/usr/bin/env bash

# required env vars:
# WORKSPACE - will contain the thin-egress-app project
# DEPENDENCYLAYERFILENAME - this script will output a zip file with this name

echo "RUNNING dependency_builder.sh"

echo "inside dependency building container env:"
printenv

yum update -y
yum install -y zip python3-devel python3-pip


mkdir -p /tmp/pkg/python


cd /tmp/pkg/python || exit

pip3 install --upgrade setuptools
pip3 install -r ${WORKSPACE}/rain-api-core/requirements.txt --target .
pip3 install -r ${WORKSPACE}/lambda/requirements.txt --target .

# get rid of unneeded things to make code zip smaller
rm -rf ./*.dist-info
# rm -rf pip # commented out because https://snyk.io/vuln/SNYK-PYTHON-PIP-609855
rm -rf docutils
rm -rf chalice/cli # cli in lambdacode? No way!
rm -rf botocore # included with lambdacode, just takes up space here
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
