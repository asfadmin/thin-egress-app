# GitHub Actions Workflows
These workflows define a CI/CD pipeline that is intended to work both for the
main repo and for forks.

GitHub Actions workflows overview:
- Run unit tests and style checks against PR's
- Run end-to-end tests whenever a PR is merged
- Build and publish zip/yaml files needed to spin up a TEA stack on releases

In order for the end-to-end tests to run you need to set the `RUN_TESTS` secret
in your repository secrets to `true`. However, currently these tests assume
they are running in ASF's environment, so enabling them is probably not desired
on forked repos, hence they are disabled by default. All other secrets are
stored in GitHub environments.

## Environments
There are two environments used to control which AWS resources will be modified
by GitHub Actions. The `prod` environment is used for pushing finished build
artifacts and build status files to a public bucket. The `test` environment is
used for deploying a test stack and running the end-to-end tests against it.
Unless you enable the end-to-end tests with the `RUN_TESTS` repository secret,
you don't need to configure any secrets in the `test` environment.

- prod
  - AWS Credentials (see below)
- test
  - AWS Credentials (see below)
  - `URS_USERNAME` URS username used by end-to-end tests for authenticated
    downloads
  - `URS_PASSWORD` URS password used by end-to-end tests for authenticated
    downloads
  - If the config file doesn't specify a value for `URS_AUTH_CREDS_SECRET_NAME`,
    the following secrets are also needed:
    - `URS_CLIENT_ID`
    - `EDL_APP_UID`
    - `EDL_APP_PASSWORD`

### Setting up AWS Credentials
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- (optional) `AWS_ROLE_ARN`
- (optional) `AWS_REGION`

## Config file
Unfortunately, GitHub currently doesn't support non-secret configuration
variables. Therefore all non-secret configuration is stored in `.env`
files located in the `config-public` directory. The file names correspond to
the environment names that the configuraiton belongs to. After forking the repo,
you can commit changes to these files to adjust the setup for your use case.

### Build Configuration
The build configuration is located in `prod.env` and includes the following
options:

- `CODE_BUCKET` Bucket to upload build results to. Needs to allow public ACL.
- (optional) `CODE_PREFIX` All objects uploaded to the code bucket get
  this prefix

### Test Configuration
The end-to-end test configuration is located in `test.env` and includes the
following options:

- `BUCKET_MAP_FILE` Name of the bucket map file to use from the config
bucket.
- `BUCKETNAME_PREFIX`
- `CODE_BUCKET` Bucket to upload build results to for testing. Probably a
  private bucket.
- `CODE_PREFIX` All objects uploaded to the code bucket get this prefix.
- `CONFIG_BUCKET` Bucket containing configuration files such as
  the bucket map. Defaults to `CODE_BUCKET`
- `COOKIE_DOMAIN`
- `DOMAIN_CERT_ARN`
- `DOMAIN_NAME`
- `JWT_KEY_SECRET_NAME` Name of the AWS SecretsManager secret
  containing the JWT public and private keys. This can be omitted and a
  secret will be created automatically with a newly generated key pair.
- `STACK_NAME` Name of the CloudFormation stack to update
- `URS_AUTH_CREDS_SECRET_NAME` Name of the AWS SecretsManager
  secret containing URS client id and client secret. This can be omitted
  and a secret will be created automatically using the following github
  environment secrets:
  - `URS_CLIENT_ID`
  - `EDL_APP_UID`
  - `EDL_APP_PASSWORD`
- `URS_URL` URL to use for Earthdata login.
