# Welcome to TEA - The Thin Egress App

![Last Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Fbuildstatus.json)
![Last Build](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastbuild.json)
![Last Good Build](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastgoodbuild.json)
[![Last Release](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastrelease.json)]((https://github.com/asfadmin/thin-egress-app/releases/latest))
![Test Results](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Ftestresults.json)
[![codecov](https://codecov.io/gh/asfadmin/thin-egress-app/branch/devel/graph/badge.svg?token=Jd5l4IVpkM)](https://codecov.io/gh/asfadmin/thin-egress-app)
[![Safety Badge](https://pyup.io/repos/github/asfadmin/thin-egress-app/shield.svg?t=1559317620375)](https://pyup.io/account/repos/github/asfadmin/thin-egress-app/)
[![CodeFactor](https://www.codefactor.io/repository/github/asfadmin/thin-egress-app/badge)](https://www.codefactor.io/repository/github/asfadmin/thin-egress-app)

A fully Earthdata Cloud (EDC) compliant
Amazon S3 distribution application.


See the [documentation](https://tea-docs.asf.alaska.edu) for a guide on
deploying TEA in a production environment.


# Development

You can deploy the CloudFormation template for development using our Makefile. You'll need to
set up your secrets and S3 buckets manually, but once that's done pushing your changes is as easy as
running `make deploy`.

```bash
# First time setup. Add your bucket and secret names to this file.
make Makefile.config

# Build and deploy to the configured AWS profile.
# Run this whenever you're ready to test your code changes.
make deploy
```

*If you are forking the repository for the purpose of making your own
releases see the [GitHub Actions README](.github/workflows/README.md).*

## Dependencies

In order to build TEA, you will need to have a few tools installed:

- `make` for build automation
- `python3.8` for running tests and creating the CloudFormation template
- `docker` for building the dependency layer
- `git` for installing rain-api-core
- `zip` for creating zip files
- `awscli` (optional) for deploying to AWS

### Python Dependencies

The Python runtime dependencies are declared in a number of `requirements.in`
files, and pinned to `requirements.txt` files using
[pip-tools](https://pypi.org/project/pip-tools/). For housekeeping purposes
these are all located in the `requirements` directory. If you need to add a
runtime dependency, put it into `requirements/requirements.in` and then run
`make lock` to generate the `requirements/requirements.txt` file. This will
run `pip-compile` in a docker container to ensure the file is compiled for a
lambda compatible environment.

```bash
# Update the pinned requirements files
make lock
```

Note that the pinned `requirements.txt` files are environment specific. i.e.
they might not be correct when run outside of a linux/awslambda environment. If
you are developing on a different platform such as MacOS, you will have to
compile your own versions of these files before you can install them locally.

```bash
# Create virtual environment for development
python3 -m venv .venv
# Activate virtual environment
source .venv/bin/activate

# Install pip-tools
# Make sure you see '(.venv)' in your shell prompt before running this!
pip install pip-tools

# Compile the dependency tree for your particular environment.
# On Linux, you can skip this and use the versions included in the source
pip-compile requirements/requirements.in -o requirements/my-requirements.txt
pip-compile requirements/requirements-dev.in -o requirements/my-requirements-dev.txt

# Install requirements to the virtual environment.
pip install -r requirements/my-requirements.txt -r requirements/my-requirements-dev.txt
```

## Local Builds
All build artifacts are created in the `dist` directory. Numerous configuration options are available through the `Makefile.config` which is created the first time you run `make` (see [Configuration](#configuration)).

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

### Configuration
After you run any `make` command for the first time, you will get a file called `Makefile.config`. This contains
any Make configuration variables that you may wish to tweak for your development purposes. If you
need to override any additional variables from the Makefile you can put them in this file.
Alternatively, if you just need to make a one off change, `make` lets you set variables on the
command line:

```bash
make deploy STACK_NAME=thin-egress-app-temp AWS_PROFILE=development
```

You will need to change any variables that have the value `REQUIRED_FOR_DEPLOY!` before you can run
`make deploy`.


#### Local Pip Dependencies
If you need to build against a local version of one of the requirements in the `requirements/requirements.txt`
such as `rain_api_core`, you will need to make a few adjustments to your `Makefile.config` for the
docker container to be able to install those dependencies.

1. Mount the local dependency as a docker volume using `DOCKER_ARGS` in your `Makefile.config`:
```makefile
DOCKER_ARGS := -v /host/path/to/rain-api-core:/var/deps/rain-api-core
```
2. Replace the dependency in the `requirements/requirements.txt` file with the
container path:
```
file:/var/deps/rain-api-core
```
*NOTE: This is a generated file and you should NOT be committing these changes*
3. Add any source files of that dependency to the `REQUIREMENTS_DEPS` in your `Makefile.config`:
```makefile
REQUIREMENTS_DEPS := $(shell find /host/path/to/rain-api-core/rain_api_core/ -name '*.py')
```

Now when you run `make build`, the dependency layer should be correctly rebuilt if any of the
source files in your local version of the dependency have changed.


## Running Tests
TEA has two types of automated tests. End-to-End tests and unit tests. The End-to-End tests rely on a lot of ASF specific resources to exist in the test environment, so they may be harder to adapt for custom builds.

### Unit Tests

The unit test suite is written using pytest. It can be run in a virtual
environment (see [Python Dependencies](#python-dependencies)) with the
following commands:

```bash
# Activate virtual environment
source .venv/bin/activate

# Run the tests
make test
```
