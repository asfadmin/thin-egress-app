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

## Table of Contents:
* [History of TEA](#history-of-tea) - A Brief History of where TEA came from
* [Purpose of TEA](#purpose-of-tea) - What TEA is and isn't
  * [TEA Vision](#tea-vision)
  * [Principles of TEA design](#principles-of-tea-design)
* [System Architecture](#system-architecture) - Components and technologies in TEA
* [External Integrations](#external-integrations) - How TEA related to other things
  * [Cumulus](#cumulus)
  * [EDL](#edl)
  * [EDC](#edc)
* [Build Process](#build-process) - Where the code comes from
  * [Code Quality](#code-quality)
    * [Linting](#linting)
    * [CVE](#cve)
    * [Static Code Analysis](#static-code-analysis)
  * [Automated Testing](#automated-testing)
  * [Roll-Your-Own](#roll-your-own)
    * [Dependency Layer](#dependency-layer)
    * [Packaging up the egress code](#packaging-up-the-egress-code)
* [Getting TEA Code](#getting-tea-code) - Where you can get TEA code and deployment mechanism
  * [github.com](#githubcom)
  * [s3://asf.public.code](#s3asfpubliccode)
* [TEA Core Features](#tea-core-features) - Configuring TEA to work for you
  * [Bucket Mapping](#bucket-mapping)
    * [Custom Headers](#custom-headers)
  * [EDL Access Control](#edl-access-control)
    * [Public Buckets](#public-buckets)
    * [Private Buckets](#private-buckets)
    * [Public and Private Prefixes](#public-and-private-prefixes)
  * [Custom Templating](#custom-templating)
  * [Shared Token Support](#shared-token-support)
  * [Dynamic In-Region IP CIDR Updates](#dynamic-in-region-ip-cidr-updates)
* [Working inside EDC](#working-inside-edc) - How to integrate into Earthdata Cloud
  * [VPC and Networking](#vpc-and-networking)
  * [VPC Endpoints](#vpc-endpoints)
  * [Permission Boundaries](#permission-boundaries)
  * [Do I need a Bastion?](#do-i-need-a-bastion)
* [Deploying TEA](#deploying-tea) - Everything required for deploying TEA
  * [Secrets Setup](#secrets-setup)
    * [URS Auth Creds Secret](#urs-auth-creds-secret)
    * [JWT Cookie Secret](#jwt-cookie-secret)
  * [From CloudFormation](#from-cloudformation)
    * [All Parameters](#all-parameters)
    * [AWS Console](#aws-console)
    * [Using awscli](#using-awscli)
  * [From Terraform](#from-terraform)
  * [From Cumulus](#from-cumulus)
  * [For development](#for-development)
* [Post deployment procedures](#post-deployment-procedures) - What do to AFTER Deploying
  * [Update EDL](#update-edl)
  * [Validating a Deployment](#validating-a-deployment)
    * [Accessing the API Gateway inside EDC](#accessing-the-api-gateway-inside-edc)
  * [Requesting an EDC Public App](#requesting-an-edc-public-app)
  * [Updating configuration of a live TEA](#updating-configuration-of-a-live-tea)
  * [Using custom domain names](#using-custom-domain-names)
* [Logs](#logs) - What TEA does with logs
  * [CloudWatch Logs](#cloudwatch-logs)
  * [Values embedded into S3 logs](#values-embedded-into-s3-logs)
* [When things go wrong](#when-things-go-wrong) - Hopefully we can help!
  * [Troubleshooting](#troubleshooting)
  * [Bug reporting/tracking](#bug-reportingtracking)
  * [Maintenance cycle & Releases](#maintenance-cycle--releases)
* [Make it better](#make-it-better) - It's not perfect, but it's getting better!
  * [Contribute](#contribute)
  * [Requesting features](#requesting-features)
* [TL;DR](#tldr) - We understand not everyone likes to read docs. We can do it for you!
  * [Walk me through this!](#walk-me-through-this)

## History of TEA

TEA was originally designed as a lightweight S3 distribution application with Earthdata Login
(EDL) support meant to help test and evaluate the (then) forethcoming NGAP Enterprise Egress
platform. TEA leveraged much of the design and features of ASF's original full-featured s3
distribution app, without any of the throttling or egress tracking capabilities. Without the
need to do throttling, TEA ditched docker/nginx/ECS in favor of the lighter, more nimble
Lambda + API Gateway architecture.

[⬆ Return to Table of Contents](#table-of-contents)

## Purpose of TEA

At the most fundamental level, TEA is intended to be a FULLY Earthdata Cloud (EDC) compliant
application to enable distribution of EOSDIS data from Amazon S3 while ensuring data
providers have all the tools, controls and metrics required for ensuring data distribution
restriction and reporting compliance. TEA Distribution supports only static S3 data, and is
not intended for service-style or dynamic data distribution.

This documentation is intended to support stand-alone TEA deployments, and while it may be a
valuable tool for TEA deployments provisioned through Cumulus, we suggest you visit cumulus
documentation for guidance on using and customizing TEA from within cumulus.

### TEA Vision

We the **TEA**m Strive to create the simplest, most reliable, most feature-rich S3
distribution app. Our intent is not to provide EVERY feature imaginable, but to maintain the
**THIN** core of broadly applicable features. We want to continue to engage the user
community to improve the feature set while staunchly resisting the siren song of feature
bloat and one-off special ponies.

### Principles of TEA design

* Keep it simple - No special ponies!
* Remove unwanted/unused code
* Write *clean* code
* Engage and support the community
* Strive for 10% community provided code base - we ❤️ PR's!


[⬆ Return to Table of Contents](#table-of-contents)

## System Architecture

In the shortest possible explanation, TEA is a [Python Chalice](https://github.com/aws/chalice)
application that leverages AWS Lambda and API Gateway to create Pre-signed S3 URLs to
facilitate user downloads over https via CloudFront.

![TEA Design](https://github.com/asfadmin/thin-egress-app/raw/devel/tea.png)

[⬆ Return to Table of Contents](#table-of-contents)

## External Integrations

TEA cannot really operate in a vacuum. TEA is part of what might be considered the Earthdata
ecosystem.

### Cumulus

TEA can be considered the "official" distribution application of Cumulus, and while there is
a symbiotic relationship, TEA is an add-on to cumulus rather than an extension. We suggest
utilizing the applicable Cumulus documentation for tightly coupled TEA+Cumulus deployments.

### EDL

The Earthdata Login OAUTH service is a requirement for distributing data where user activity
tracking and reporting is required. Before deploying TEA, it is important to have access to,
or [create a new EDL Application](https://urs.earthdata.nasa.gov/apps/new). Creating and
administrating an EDL Application requires the EDL App Admin role, which must be requested
through the feedback modal in the Earthdata login header menu.

### EDC

While TEA can be deployed outside of the Earthdata Cloud, it is designed and intended to be
used within the Earthdata Cloud environment. While we assume you'll be deploying to the EDC,
we cannot provide assistance in setting up or configuring access to EDC. However, when there
are steps or considerations that are required for integration into EDC, we will help ensure
you have all the information you need to do the right thing.


[⬆ Return to Table of Contents](#table-of-contents)

## Build Process

![build-process](https://github.com/asfadmin/thin-egress-app/blob/devel/tea-build.png)

### Code Quality

TEA leverages several open source platforms along with mandatory peer code review to help
ensure the code base is clean, stable, and secure

#### Linting

CodeFactor.io github integrations provide merge request blocking based on appropriate levels
of code linting.

#### CVE

PyUp, Snyk and Whitesource all provide Common Vulnerabilities and Exposures (CVE) Analysis.
Emergent CVE fixes are automatically pushed to the TEA repo as merge requests and merged into
the repo as soon as possible.

#### Static Code Analysis

CodeFactor.io and Whitesource provide merge request block based on Static Code Analysis to
help ensure our code is secure and safe to run.

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

### Roll-Your-Own

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

[⬆ Return to Table of Contents](#table-of-contents)

## Getting TEA Code

Major release documentation can be found
[in github](https://github.com/asfadmin/thin-egress-app/releases/latest).

### github.com

Raw TEA code is broken into two github repos:
 * [thin-egress-app](https://github.com/asfadmin/thin-egress-app/) -
     Chalice App, infrastructure-as-code, build scaffolding
 * [rain-api-core](https://github.com/asfadmin/rain-api-core/) -
     EDL, AWS, Session Management helper functions

### s3://asf.public.code

All public releases of ASF code are made available via the public bucket
[asf.public.code](https://s3.amazonaws.com/asf.public.code/index.html). Each build has 4
files:

* **tea-cloudformation-build.#.yaml** - CloudFormation template
* **tea-code-build.#.zip** - Lambda App Python Code
* **tea-dependencylayer-build.#.zip** - Lambda layer Python Dependency Code
* **tea-terraform-build.#.zip** - TEA as a Terraform module (For cumulus!)

[⬆ Return to Table of Contents](#table-of-contents)

## TEA Core Features

### Bucket Mapping

At the heart of TEA is the concept of the Bucket Map. This YAML file tells TEA how to
map URLs to buckets and how to control access to data in buckets. Mapping depths are
arbitrary and dynamically account for object path prefixes. Bucket maps are case
sensitive!

When working with a bucket map, it is important to remember that bucket names are
relative to the optional `bucket prefix` TEA parameter. If a `bucket prefix` is
supplied, that value is prepended to any bucket name. This optional feature is intended
to allow bucket maps to be used in multiple maturities (e.g. Sandbox, SIT, UAT, Prod)
where bucket names are consistent across maturities given a specific bucket prefix.

Assume the following bucket map:

```yaml
MAP:
  path1: bucket-path-1

  path2:
    path2a: bucket-path-2a
    path2b: bucket-path-2b

  path3:
    path3a:
      path3ai: bucket-path-3ai
```

You can derive the following object -> URL mappings:
```
s3://bucket-path-1/object.txt           => https://[APP-BASE-URL]/path1/object.txt
s3://bucket-path-2a/file.ext            => https://[APP-BASE-URL]/path2/path2a/file.ext  
s3://bucket-path-2b/low-res/browse.jpg  => https://[APP-BASE-URL]/path2/path2b/low-res/browse.jpg
s3://bucket-path-3ai/some-product.h5    => https://[APP-BASE-URL]/path3/path3a/path3ai/some-product.h5
```

It is **NOT** possible to have distribution at the app root. That is,
`s3://bucket-path-1/object.txt` cannot be configured to be distributed at
`https://[APP-BASE-URL]/object.txt`.

#### Custom Headers

Custom HTTP response headers can be added to bucket mappings:

```yaml
MAP:         
  path1:
      bucket: bucket-path-1
      headers:
        Content-Type: "text/plain"
```

### EDL Access Control

By default, all buckets are assumed to require a user to log into Earthdata Login to
download data. However, there are two options to change that behavior

#### Public Buckets

Buckets can be made public by adding a `PUBLIC_BUCKETS` block:

```yaml
MAP:
   browse: browse-bucket

PUBLIC_BUCKETS:
   browse-bucket:  "Internal only Comment about browse being public"
```

In the above example, accessing `https://[APP-BASE-URL]/browse/some-browse-image.jpg`
would not require EDL authentication, however, if a user was already logged in, the
downloads would be tagged with that users EDL User ID.

#### Private Buckets

TEA download can also be restricted to users who belonging to an EDL Application
User Group. This allows App and Data owners to specify a discrete list of specially
approved users who can download data.

```yaml
MAP:
   pre-commission: pre-comission-data-bucket

PRIVATE_BUCKETS:
   pre-commission-data-bucket:
     - internal_users
     - external_team
```

In the example above, TEA will ensure that a user attempt to download
`https://[APP-BASE-URL]/pre-commission/not-yet-public.zip` belongs to **either**
the App User Group `internal_users` or `external_team`. Users who are not in one or
both of those groups will not be granted a download.

#### Public and Private Prefixes

In addition you specifying whole buckets as Public or Private, you can also use
object prefixing to control access:

```yaml
MAP:
   data-bucket: data-bucket

PUBLIC_BUCKETS:
   data-bucket/browse: "Browse image"

PRIVATE_BUCKETS:
   data-bucket/pre-commission-data:
     - internal_users
     - external_team
```

In the above example, while access data in `data-bucket` requires simple auth,
accessing an object with the prefix `browse/` will require NO auth, and
`pre-commission-data/` will require EDL App group access as specified.

### Custom Templating

You may optionally create your own [jinja2](http://jinja.pocoo.org/docs/2.10/) html
templates. If no custom templates are supplied in the `HtmlTemplateDir` subdirectory
of the `ConfigBucket` bucket, ultra-generic (and a little annoying!)
[default templates](https://github.com/asfadmin/thin-egress-app/tree/devel/lambda/templates)
are used.

**base.html**
This is the base template.

Blocks:
 * `pagetitle`: Gets inserted inside the `<title></title>` element
 * `content`: Content payload fed into the template.

**root.html**
Child template. Gets called by `/` and `/logout` for 200 responses.

Variables:
 * `title`: page title
 * `URS_URL`: used to make the login link
 * `STAGE`: used to make a URL back to the egress app
 * `profile`: in the default template, `profile.first_name` and `profile.last_name` are used to greet a logged-in user. The entire profile dict is available to the template.
 * `contentstring`: any text can go here

**error.html**
Child template that gets called when various 400 type errors happen.

Variables:
 * `title`: page title
 * `status_code`: http status code goes here
 * `contentstring`: any text can go here

**profile.html**
Child template that displays profile info. Only used for debugging in dev.

### Shared Token Support

TEA can accept a shared EDL Token as an Authorization (Bearer Token) method. To
enable this behavior, EDL Apps (Service + TEA) must belong to a shared EDL App
Group. Processing a shared token is temporally expensive. After the initial
request, subsequent Service->TEA data requests should reuse cookies. EULA
enforcement is preserved with shared tokens.

![TEA](https://github.com/asfadmin/thin-egress-app/blob/devel/harmony-chain.png)

### Dynamic In-Region IP CIDR Updates

TEA deploys a Lambda, triggered by a subscription to the SNS Topic
`arn::aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged`, which downloads the
AWS Provided [ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json)
file, parses out the IP CIDRs for the deploy region, and automatically updates
the In-Region IAM Role's Policy Document `condition` block.

This lambda is defined in
[update_lambda.py](https://github.com/asfadmin/thin-egress-app/blob/master/lambda/update_lambda.py)

[⬆ Return to Table of Contents](#table-of-contents)

## Working inside EDC

While TEA is primarily designed to be deployed inside EDC, below are some
important configurations to be aware of to make deploying to EDC Successful.

### VPC and Networking

This bash script will give you all the parameters you'll need to deploy into EDC:

```bash
export AWS_REGION='us-west-2'
export AWS_PROFILE='default'
export AWSENV="--profile=${AWS_PROFILE} --region=${AWS_REGION}"
export VPCID=$(aws $AWSENV ec2 describe-vpcs --query "Vpcs[*].VpcId" --filters "Name=tag:Name,Values=Application VPC" --output text)
export SUBNETID=$(aws $AWSENV ec2 describe-subnets --query "Subnets[?VpcId=='$VPCID'].{ID:SubnetId}[0]" --filters "Name=tag:Name,Values=Private*" --output=text)
export SECURITYGROUP=$(aws $AWSENV ec2 describe-security-groups --query "SecurityGroups[?VpcId=='$VPCID'].{ID:GroupId}" --filters "Name=tag:Name,Values=Application Default*" --output=text)
echo "PrivateVPC=$VPCID; VPCSecurityGroupIDs=$SECURITYGROUP; VPCSubnetIDs=$SUBNETID;"
```

### VPC Endpoints

It is also important to be aware that an API Gateway VPC Endpoint will need to
be setup prior to deployment. You can check to see if your account has the
appropriate VPCE by running this command:

```bash
aws $AWSENV ec2 describe-vpc-endpoints --query "VpcEndpoints[?(VpcId=='$VPCID' && ServiceName=='com.amazonaws.${AWS_REGION}.execute-api')].{ID:VpcEndpointId}" --output=text
```

### Permission Boundaries

When deploying into NGAP, it is important to supply a Permission Boundary. This
allows CloudFormation to create necessary IAM roles on your behalf.

### Do I need a Bastion?

The answer is that it certainly helps. If your account does not have a bastion,
validating a deployment will be very difficult.

[⬆ Return to Table of Contents](#table-of-contents)

## Deploying TEA

At its core, TEA uses a CloudFormation template to deploy all of its resources to
AWS. Additionally, there is an available [Terraform module](#from-terraform) that can be used on its
own, or as an add-on to Cumulus.

### Secrets Setup

Two secrets manager objects are required for TEA to function properly:

#### URS Auth Creds Secret

To set up the URS Auth secret object, You'll need these parameters:

* `UrsId` can be found on your SSO application's URS home page as `Client ID`.
* `UrsAuth` is the `UID` for your URS SSO app and password separated by a colon.
You can create the value with the command below. See EDL's
[Request Authorization Code](https://urs.earthdata.nasa.gov/sso_client_impl)
documentation for more details.

Encode the Creds
```bash
UrsAuth=$(echo -n "<App UID>:<App Password>" | base64)
UrsId="<Client ID>"
```

Write the base64 encoded keys into a json file:
```bash
cat << EOL > urscreds.json
{
    "UrsId": "$UrsAuth",
    "UrsAuth": "$UrsId"
}
EOL
```

Create the secret in AWS, referencing the json file created above
```bash
aws $AWSENV secretsmanager create-secret --name urs_creds_for_tea \
    --description "URS creds for TEA app" \
    --secret-string file://urscreds.json
```

#### JWT Cookie Secret

JWT secrets allow multiple TEA instances to encode and decode each others JWT
cookies. This helps reduce the number of times EDL Authentication needs to
happen.  There are many ways to create JWS Secrets, here is one example:

First, Create a key pair and b64 encode them:
```bash
ssh-keygen -t rsa -b 4096 -m PEM -f ./jwtcookie.key
rsa_priv_key=$(openssl base64 -in jwtcookie.key -A)
rsa_pub_key=$(openssl base64 -in jwtcookie.key.pub -A)
```
Put the base-64 encoded keys into a json file like so:
```bash
cat << EOL > jwtkeys.json
{
    "rsa_priv_key": "$rsa_priv_key",
    "rsa_pub_key":  "$rsa_pub_key"
}
EOL
```
Create the secret in AWS, referencing the json file created above
```bash
aws $AWSENV secretsmanager create-secret --name jwt_secret_for_tea \
    --description "RS256 keys for TEA app JWT cookies" \
    --secret-string file://jwtkeys.json
```
### From CloudFormation

#### All Parameters
 * **App Settings**:
   * `Loglevel` - How verbose the logging should be
   *  `Logtype` - How log entries are formed. Use json in conjunction with log analysis tools. Use flat for human debugging.
   * `Maturity` - Maturity, mostly for logs
   * `ConfigBucket` - S3 bucket where configuration files (bucket map, templates) are kept
   * `HtmlTemplateDir` - (OPTIONAL) Subdirectory of `ConfigBucket` where templates can be found
   * `StageName` - API Gateway Stage value
   * `EnableApiGatewayLogToCloudWatch` - Whether or not API Gateway logs should be dumped
* **Domain Settings**:
   * `DomainName` - (OPTIONAL) domain name as a user will access it (ie CloudFront, CNAME, etc)
   * `CookieDomain` - (OPTIONAL) domain name value for minting cookies
   * `DomainCertArn` - (OPTIONAL) Arn to a AWS ACM SSL Cert for HTTPS access
   * `UseCorsCookieDomain` - If `True`, and `CookieDomain` is set, this enables CORS Response Headers  
* **Lambda Code**:
   * `LambdaCodeS3Bucket` - S3 bucket where Lambda code zip files are kept
   * `LambdaCodeS3Key` - Object name of Lambda code zip
   * `LambdaCodeDependencyArchive` - Object name of Lambda Dependency Layer zip
   * `LambdaTimeout` - Lambda timeout in seconds
   * `LambdaMemory` - The amount of memory available to the function during execution. Must be multiple of 64. Minimum: 128. Max: 3008. Default 1792.
* **URS Settings**:
   * `URSAuthCredsSecretName` - [URS Auth Creds Secret](#urs-auth-creds-secret)
   * `AuthBaseUrl` - Which maturity of URS to hit
* **Data Bucket Setup**:
   * `BucketnamePrefix` - (OPTIONAL) Bucket prefix value (see [Bucket Mapping](#bucket-mapping))
   * `BucketMapFile` - bucket map YAML file (see [Bucket Mapping](#bucket-mapping))
   * `UseReverseBucketMap` - Ignore this value!
   * `DownloadRoleArn` - (OPTIONAL) Pre-created IAM Role for minting presigned urls
     * Leave blank to create a new role for deployment
   * `DownloadRoleInRegionArn` - (OPTIONAL) Pre-created IAM Role for minting IN-REGION presigned urls
     * Leave blank to create a new role for deployment
   * `SuppressHeadCheck` - Disable the pre-sign object validation. Enable for speedier access.
* **Session Settings**:
   * `SessionTTL` - How long, in seconds, JWT Cookies are valid for
   * `JwtAlgo` - JWT Signing algorithm
   * `JwtKeySecretName` - [JWT Cookie Secret](#jwt-cookie-secret)
* **NGAP Integration**: ⚠️ These are **REQUIRED** for EDC Deployments. See
[VPC and Networking](#vpc-and-networking)
   * `PrivateVPC` - Private VPC ID in which we create resources (`$VPCID`)
   * `VPCSecurityGroupIDs` - Security group (`$SUBNETID`)
   * `VPCSubnetIDs` - VPC Subnets to deploy into (`$SECURITYGROUP`)
   * `PermissionsBoundaryName` - Permissions Boundary used for creating IAM Roles;
probably `NGAPShRoleBoundary`

#### AWS Console

Originally, I was going to walk through deploying TEA via the AWS
CloudFormation web console, but there are
[better guides](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stack.html)
out there. So, instead, I'd just remind you that you need [THREE files](#getting-tea-code):

* This file will be uploaded to the CloudFormation web console:
  * **tea-cloudformation-build.#.yaml**
* These two zips need to be uploaded to a bucket in your account:
  * **tea-code-build.#.zip**
  * **tea-dependencylayer-build.#.zip**

#### Using awscli

As with [AWS Console](#aws-console) deployments, you'll need to upload the
two zip files to a code bucket in your account.  After doing that, be sure you've
sourced the [VPC and Networking](#vpc-and-networking) parameters as well as create
the two required [Secrets](#secrets-setup).

```bash
# Code path variables
CF_TEMPLATE_FILE=/local/path/to/tea-cloudformation-build.#.yaml
CODE_BUCKET=my-tea-code-bucket
CODE_ARCHIVE_FILENAME=tea-code-build.#.zip
DEPENDENCY_LAYER_FILENAME=tea-dependencylayer-build.#.zip
BUCKETMAP_FILENAME=my_bucketmap.yaml
CFG_BUCKETNAME=my-tea-cfg

# See the Cloudformation parameters section above for a description of these params.
STACK_NAME=my-tea # needs to be compatible with S3 naming requirements (lower case, no underscores, etc)
                  # because the CF template may create buckets using this name.
AWS_REGION=us-west-2 # Or another region if desired.
AWS_PROFILE=default  # Or whichever awscli profile you want to deploy to.

# Deploy the stack
aws cloudformation deploy --profile=${AWS_PROFILE} --region=${AWS_REGION} \
  --stack-name ${STACK_NAME} \
  --template-file ${CF_TEMPLATE_FILE} \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
        AuthBaseUrl=https://uat.urs.earthdata.nasa.gov \
        BucketMapFile=${BUCKETMAP_FILENAME} \
        ConfigBucket=${CFG_BUCKETNAME} \
        EnableApiGatewayLogToCloudWatch="False" \
        JwtAlgo="RS256" \
        JwtKeySecretName="jwt_secret_for_tea" \
        LambdaCodeDependencyArchive={DEPENDENCY_LAYER_FILENAME} \
        LambdaCodeS3Bucket=${CODE_BUCKET} \
        LambdaCodeS3Key=${CODE_ARCHIVE_FILENAME} \
        LambdaTimeout=6 \
        Loglevel=INFO \
        Logtype=json \
        Maturity=DEV \
        PermissionsBoundaryName=NGAPShRoleBoundary \
        PrivateVPC=$VPCID \
        SessionTTL=168 \
        StageName=API \
        URSAuthCredsSecretName="urs_creds_for_tea" \
        UseReverseBucketMap="False" \
        UseCorsCookieDomain="False" \
        VPCSecurityGroupIDs=$SECURITYGROUP \
        VPCSubnetIDs=$SUBNETID

```
### From Terraform

Why would you want to deploy it from Terraform? Just use
[CloudFormation](#from-cloudformation)! But for real, if someone wants to do
a write up for this, I'd love to include it.

### From Cumulus

Please see the
[Cumulus documentation](https://nasa.github.io/cumulus/docs/deployment/thin_egress_app)
for current TEA deployment and configuration procedures.

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

[⬆ Return to Table of Contents](#table-of-contents)

## Post deployment procedures

Once a TEA stack has been successfully deployed, there are still a few
remaining steps that need to be completed before users can start downloading
data.

### Update EDL

After deploying TEA, you'll need to add the new URI to your EDL App's authorized
redirect URIs. To get the proper value, you can query the cloudformation stack:

```bash
aws $AWSENV cloudformation describe-stacks \
            --stack-name=$STACK_NAME \
            --query 'Stacks[0].Outputs[?OutputKey==`URSredirectURI`].OutputValue' \
            --output=text
```

### Validating a Deployment

TEA has a `/version` endpoint you can use to check that a deployment is healthy
and responsive:

```bash
api_endpoint=$(aws $AWSENV cloudformation describe-stacks \
                           --stack-name=$STACK_NAME \
                           --query 'Stacks[0].Outputs[?OutputKey==`ApiEndpoint`].OutputValue' \
                           --output=text)
curl ${api_endpoint}version
```

#### Accessing the API Gateway inside EDC

It's important to understand that in the EDC, you can't do the above step.
There is no route into the VPC from the general internet. There are
write-ups elsewhere that go into depth on how to proxy HTTPS requests into
the private VPC.

### Requesting an EDC Public App

To access TEA from outside the private VPC, you'll need to make a [Publish
New App](https://bugs.earthdata.nasa.gov/servicedesk/customer/portal/7/create/94)
NASD request.

After the NASD has been processed and a new CloudFront domain is generated
for your TEA deployment, you'll need to update the `DomainName` and `CookieName`
parameters of your [TEA Deployment](#all-parameters) with the new CloudFront
domain name.

### Updating configuration of a live TEA

If the bucket map is updated, because of caching it can take quite some time before TEA loads it.
If you would like to force TEA to load the new configs immediately, invoke the bumper lambda:
```bash
aws $AWSENV lambda invoke --function-name="${STACK_NAME}-BumperLambda" output.txt
```

### Using custom domain names

There is a process by which you can request an Alternate Domain name to your
CloudFront endpoint. If you do this, you'll need to update the `DomainName`,
`CookieName`, and `DomainCertArn` parameters of your
[TEA Deploment](#all-parameters).

[⬆ Return to Table of Contents](#table-of-contents)

## Logs

The two primary locations where you can see the affects of TEA in the logs.

### CloudWatch Logs

TEA Creates two log streams:

* **`/aws/lambda/<STACK_NAME>-EgressLambda`** - This is where App logs go
* **`/aws/lambda/<STACK_NAME>-UpdatePolicyLambda`** - Logs from the Lambda that
keeps the in-region CIDR list up to date in the in-region download role.

### Values embedded into S3 logs

When TEA generates a pre-signed S3 download URL, it adds a query parameter
`A-userid`, the value of which is the EDL User ID, if any, that was used to
download the data. This parameter is available to be mined out of the S3
access logs.

When CloudFront is deployed in front of TEA, that `A-userid` parameters is
also added to the s3 download request that CloudFront generates. CloudFront
will also add a `sourceip` parameter that holds the true IP of the external
user.

[⬆ Return to Table of Contents](#table-of-contents)

## When things go wrong

There is a lot that _can_ go wrong, but we hope that if you followed this
guide, you'll have prevented many of the common problems. If not, start
here!

### Troubleshooting

#### Error message:
If you see an error message in the Cloudformation Events like this:
> CloudWatch Logs role ARN must be set in account settings to enable logging (Service: AmazonApiGateway; Status Code: 400; Error Code: BadRequestException; ...

#### Solution:

`EnableApiGatewayLogToCloudWatch` is set to `True`. If you don't need API Gateway logging to cloudwatch, set to `False`. If you do, you must create a role with write access to Cloudwatch Logs and add its ARN here: `https://console.aws.amazon.com/apigateway/home?region=<REGION>#/settings`.

#### Updating Cached Values:

For efficiency, TEA will cache configuration into the Lambda run environment.
Certain changes, like modifications to the bucket map or secrets, may not be
immediately picked up. Lambda run times will eventually time out, but you can
force refetching of cached values be simply adding a dummy environment
variable to the running Lambda environment. There may be a better way to
trigger Lambda environment flushing, lets us know if you find a way.


### Bug reporting/tracking

First step when you encounter an error is to check the
[Troubleshooting](#troubleshooting) section. If your problem is not there,
feel free to reach out in the `#tea-pot` Slack Channel. If your problem
can't be resolved, we'll put in a
[Github Issue](https://github.com/asfadmin/thin-egress-app/issues) to help
track the problem and seek resolution.

### Maintenance cycle & Releases

We have no concrete cycle. If nothing else, we'll do periodic releases to
help resolve CVE issues.

[⬆ Return to Table of Contents](#table-of-contents)

## Make it better

Join us in this journey! Together we can make TEA better!

### Contribute

We love contributions from outside the team! We have 2 requirements for
accepting contributions:

* All contributions should conform to our [TEA Vision](#tea-vision)
* Contributions should come with unittests to validate the feature

### Requesting features

If you have a feature you'd like to request, first confirm the feature
aligns with our [TEA Vision](#tea-vision). If you think the feature
belongs in TEA, you have TWO options:

* Request the feature using [Github Issue](https://github.com/asfadmin/thin-egress-app/issues)
* Request the feature in the `#tea-pot` Slack Channel

[⬆ Return to Table of Contents](#table-of-contents)

## TL;DR

There are LOTS of words in this document. Lots of steps. Lots of ways
things can go wrong. It's understandable that you might not be
interested reading all the words and performing all the steps. In that
case, try our magic bootstrapping script!

### Walk me through this!

You can either download [`deploy.sh`](https://github.com/asfadmin/thin-egress-app/blob/devel/build/deploy.sh)
and run it, or, as show below, curl the output directly into bash.

This bash script requires `curl`,
[`awscli`](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html),
[`Session Manager Plugin`](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html),
and [`jq`](https://github.com/stedolan/jq/wiki/Installation) to be
installed.

Run `deploy.sh` by replacing all `<VARIABLES>` with the appropriate
values. `STACK-NAME` should be less than 20 characters, lower-case
letters, numbers, or `-`. It should also be globally unique.

```bash
curl -s 'https://raw.githubusercontent.com/asfadmin/thin-egress-app/devel/build/deploy.sh' | bash /dev/stdin \
            --stack-name=<STACK-NAME> \
            --aws-profile=<AWS-PROFILE-NAME \
            --bastion="<SSM-BASTION-NAME>" \
            --key-file=<LOCAL-PATH-TO-YOUR-PRIVATE-KEY> \
            --uid=<EDL-APP-UID> \
            --client-id=<EDL-APP-CLIENT-ID> \
            --pass='<EDL-APP-PASSWORD>' \
            --maturity=<SBX|DEV|SIT|INT|UAT|TEST|PROD>  \
            --edl-user-creds='<EDL-USERNAME>:<EDL-PASSWORD>'
```

All parameters are optional, but not supplying params affects behavior.

[⬆ Return to Table of Contents](#table-of-contents)
