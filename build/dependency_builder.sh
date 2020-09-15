#!/usr/bin/env bash

# requirements.txt should be at /depbuild/in/requirements.txt
# output goes /depbuild/out
# ZIPFILENAME

yum update -y
yum install -y zip python3-devel python3-pip

mkdir -p /depbuild/pkg/python
export depbuild=${DEPBUILD:-"/depbuild/"}

cd ${depbuild}pkg/python || exit

pip3 install --upgrade setuptools
pip3 install -r ${depbuild}in/requirements_tea.txt --target .
pip3 install -r ${depbuild}in/requirements_rain-api-core.txt --target .

# get rid of unneeded things to make code zip smaller
rm -rf ./*.dist-info
rm -rf pip
rm -rf docutils
rm -rf chalice/cli # cli in lambda? No way!
rm -rf botocore # included with lambda, just takes up space here
rm -rf setuptools
rm -rf tests
rm -rf easy_install.py
rm -f typing.py # MUST be removed, its presence causes error every time

cd ..

echo "zipping to ${depbuild}out/${ZIPFILENAME}"


zip -r9 "${depbuild}out/${ZIPFILENAME}" .

echo "all done"
