# Welcome to TEA - The Thin Egress App

![Last Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Fbuildstatus.json)
![Last Build](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastbuild.json)
![Last Good Build](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastgoodbuild.json)
[![Last Release](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastrelease.json)]((https://github.com/asfadmin/thin-egress-app/releases/latest))
![Test Results](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Ftestresults.json)
[![codecov](https://codecov.io/gh/asfadmin/thin-egress-app/branch/master/graph/badge.svg?token=Jd5l4IVpkM)](https://codecov.io/gh/asfadmin/thin-egress-app)
[![Safety Badge](https://pyup.io/repos/github/asfadmin/thin-egress-app/shield.svg?t=1559317620375)](https://pyup.io/account/repos/github/asfadmin/thin-egress-app/)
[![CodeFactor](https://www.codefactor.io/repository/github/asfadmin/thin-egress-app/badge)](https://www.codefactor.io/repository/github/asfadmin/thin-egress-app)

If you want the fastest path between 0 and S3 distribution, see the [TL;DR](#tldr) section
for a quick and easy TEA bootstrapping script.


### For development
You can deploy the CloudFormation template for development using our Makefile. You'll still need to
set up your secrets and S3 buckets manually, but once that's done pushing your changes is as easy as
running `make deploy`.

```bash
# First time setup. Add your bucket and secret names to this file.
make Makefile.config

# Build and deploy to the configured AWS profile.
# Run this whenever you're ready to test your code changes.
make deploy
```

### Roll-Your-Own
*If you will forking the repository for the purposes of making your own
releases see the [GitHub Actions README](.github/workflows/README.md).*

If you prefer to roll your own zip for the lambda code you can use our Makefile to build it
from source in a bash environment. You will need to have a few tools installed for this to work:

- `zip` for creating zip files
- `docker` for building the dependency layer
- `awscli` (optional) for deploying to AWS

If you're building the dependency layer locally (generally not recommended especially not on MacOS)
you will also need:
- `python3.8` with `pip`
- `git` for installing rain-api-core

All build artifacts are created into the `dist` directory.
```bash
# Clean up from previous builds
make clean

# Creates the lambda code zip: dist/thin-egress-app-code.zip
make code
# Creates the dependnecy layer zip: dist/thin-egress-app-dependencies.zip
make dependencies
# Creates the CloudFormation template: dist/thin-egress-app.yaml
make yaml
# Creates the Terraform zip file needed by cumulus
make terraform

# Creates all of the above
make build
```

You can deploy these artifacts to a development stack with
```bash
make deploy
```
*Note: You can run this command as many times as you like, make will automatically detect
changes made to the source code and rebuild/update the stack as needed*

#### Configuration
After you run any `make` command, you will notice a file called `Makefile.config`. This contains
any Make configuration variables that you may wish to tweak for your development purposes. If you
need to override any additional variables from the Makefile you can put them in this file.
Alternatively, if you just need to make a one off change, `make` lets you set variables on the
command line:

```bash
make deploy STACK_NAME=thin-egress-app-temp AWS_PROFILE=development
```

You will need to change any variables that have the value `REQUIRED!` before you can run
`make deploy`.

#### Dependency Layer

```bash
# get the repo
git clone https://github.com/asfadmin/thin-egress-app
cd thin-egress-app

# Build the zip file
make dependencies

# Upload to S3
aws s3 cp --profile=default dist/thin-egress-app-dependencies.zip s3://${CODE_BUCKET}/
```

*Note: If you are expecting the `cryptography` dependency to be built from source, you may need to
run these commands in an `amazonlinux:2` docker container. However, as `cryptography` distributes
`manylinux` wheels, this should not be necessary*

#### Packaging up the egress code:

```bash
# Get the repo
git clone https://github.com/asfadmin/thin-egress-app
cd thin-egress-app

# Build the zip file
make code

# Upload to S3
aws s3 cp --profile=default dist/thin-egress-app-code.zip s3://${CODE_BUCKET}/
```


#### Configuring local pip dependencies
If you need to build against a local version of one of the requirements in the `requirements.txt`
such as `rain_api_core`, you will need to make a few adjustments to your `Makefile.config` for the
docker container to be able to install those dependencies.

1. Mount the local dependency as a docker volume using `DOCKER_ARGS` in your `Makefile.config`:
```makefile
DOCKER_ARGS := -v /host/path/to/rain-api-core:/var/task/rain-api-core
```
2. Add the container path to the `requirements.txt` file:
```
file:/var/task/rain-api-core
```
3. Add any source files of that dependency to the `REQUIREMENTS_DEPS` in your `Makefile.config`:
```makefile
REQUIREMENTS_DEPS := $(shell find /host/path/to/rain-api-core/rain_api_core/ -name '*.py')
```

Now when you run `make build`, the dependency layer should be correctly rebuilt if any of the
source files in your local version of the dependency have changed.


### Automated Testing

Along with full-project human-executed manual regression testing, TEA also uses the Python
unittest framework (admittedly somewhat unconventionally) to run comprehensive integration
tests on freshly deployed stacks for every build. All test failures prevent successful
builds and code cannot be released without all tests completing successfully.

There is also a comprehensive unit test suite written using pytest. You can run it in a virtual
environment like this:

```bash
# Create virtual environment
python3 -m venv .venv
# Activate virtual environment
source .venv/bin/activate

# Install requirements to the virtual environment.
# Make sure you see '(.venv)' in your shell prompt before running this!
pip install -r requirements.txt -r requirements-dev.txt

# Run the tests
make test
```
