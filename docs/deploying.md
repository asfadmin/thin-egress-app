## Quickstart

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

## Getting TEA Code

Major release documentation can be found
[on github](https://github.com/asfadmin/thin-egress-app/releases/latest).

### s3://asf.public.code

All public releases of ASF code are made available via the public bucket
[asf.public.code](https://s3.amazonaws.com/asf.public.code/index.html). Each build has 4
files:

* **tea-cloudformation-build.#.yaml** - CloudFormation template
* **tea-code-build.#.zip** - Lambda App Python Code
* **tea-dependencylayer-build.#.zip** - Lambda layer Python Dependency Code
* **tea-terraform-build.#.zip** - TEA as a Terraform module (For cumulus!)


## Deployment Steps

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
   * `BucketnamePrefix` - (OPTIONAL) Bucket prefix value (see [Bucket Mapping](configuration.md#bucket-mapping))
   * `BucketMapFile` - bucket map YAML file (see [Bucket Mapping](configuration#bucket-mapping))
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

See [this guide](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stack.html)
for deploying the CloudFormation template using the AWS web console.
You'll need [three files](#getting-tea-code):

* This file will be uploaded to the CloudFormation web console:
  * **tea-cloudformation-build.#.yaml**
* These two zips need to be uploaded to a bucket in your account:
  * **tea-code-build.#.zip**
  * **tea-dependencylayer-build.#.zip**

#### Using awscli

As with [AWS Console](#aws-console) deployments, you'll need to upload the
two zip files to a code bucket in your account.  After doing that, be sure
you've sourced the [VPC and Networking](#vpc-and-networking) parameters as
well as create the two required [Secrets](#secrets-setup).

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
