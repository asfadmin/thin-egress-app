# TEA (Thin Egress App)
![TEA](https://github.com/asfadmin/thin-egress-app/blob/devel/tea.png)
## About
The Thin Egress App is an app running in lambda that creates temporary S3 links and provides URS integration. It provides a lightweight egress solution for when you don't need to throttle or cut off egress.

![Last Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Fbuildstatus.json)
![Test Results](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Ftestresults.json)
![Last Build](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastbuild.json)
![Last Good Build](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastgoodbuild.json)
![Last Release](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastrelease.json)
[![Safety Badge](https://pyup.io/repos/github/asfadmin/thin-egress-app/shield.svg?t=1559317620375)](https://pyup.io/account/repos/github/asfadmin/thin-egress-app/)
[![CodeFactor](https://www.codefactor.io/repository/github/asfadmin/thin-egress-app/badge)](https://www.codefactor.io/repository/github/asfadmin/thin-egress-app)

## Setup and Deploying

### Prerequisites:
* An application on [Earthdata URS](https://urs.earthdata.nasa.gov/apps/new)
  * Must use `OAuth 2`
* A bucket map yaml file in a config bucket
* The buckets described in the bucket map must exist. 
  * These need not be in the same account as the egress app.
  * It would help if there were some data in them.
* A secret in the [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/managing-secrets.html) containing URS client ID and auth
  * This secret should have two rows, one with key `UrsId` and the other `UrsAuth`. This is described in more detail below.
* A secret in the AWS Secrets manager for the JWT keys:
  * This secret should have two rows, `rsa_priv_key` containing the base-64 encoded RSA private key and `rsa_pub_key` containing the base-64 encoded RSA public key. This is described in more detail below.


Optional:
* A domain name and SSL cert for the service.
* An [IAM Role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) the lambda can assume to read the files in the data buckets. One will be created if not provided.
* An IAM Role that allows for only in-region access the lambda can assume to read the files in the data buckets. One will be created if not provided.
* An IAM Role that allows the API gateway to write to CloudWatch, if `EnableApiGatewayLogToCloudWatch` is set to `True`. 

### Getting the software

#### Option 1: Using pre-packaged lambda code
Pre-packaged versions of the lambda code and associated cloudformation YAML are in S3 in [ASF's public code bucket](https://s3.amazonaws.com/asf.public.code/index.html). Download the YAML for the build you want and follow the instructions below depending which region you're deploying to.

##### Option 1a: You are deploying in us-east-1:
When deploying, use the default `LambdaCodeDependencyArchive`, `LambdaCodeS3Bucket`, and `LambdaCodeS3Key` values.

##### Option 1b: You are deploying outside of us-east-1:
If you are deploying in another region, you must upload the lambda and dependency layer zip files to a bucket in your region and make sure the `LambdaCodeDependencyArchive`, `LambdaCodeS3Bucket`, and `LambdaCodeS3Key` values point to your zip files.


#### Option 2: Packaging lambda code yourself

If you prefer to roll your own zip for the lambda code:

#### Dependency Layer
We've found that if the dependency layer isn't built in an `amazonlinux:2` environment, the JWT crypto doesn't work. Here are instructions for gathering and packaging the dependencies in an `amazonlinux` docker container.
```bash

# Make up a filename for code archive:
DEPENDENCYLAYERFILENAME=tea_depencency_layer.zip

# get the repo
git clone https://github.com/asfadmin/thin-egress-app
cd thin-egress-app

# copy requirements to a directory that 
cp rain-api-core/requirements.txt lambda/requirements_rain-api-core.txt
cp lambda/requirements.txt lambda/requirements_tea.txt
cp build/dependency_builder.sh lambda/

docker run --rm -v lambda/:/depbuild/in -v ./:/depbuild/out -e "ZIPFILENAME=${DEPENDENCYLAYERFILENAME}" amazonlinux:2  bash /depbuild/in/dependency_builder.sh

# Upload to S3
aws s3 cp --profile=default ./${DEPENDENCYLAYERFILENAME} s3://${CODE_BUCKET}/
```

Packaging up the egress code:

```bash

# Make up a filename for code archive:
CODE_ARCHIVE_FILENAME=thin-egress-app-code.zip

# get the repo
git clone https://github.com/asfadmin/thin-egress-app
cd thin-egress-app

# Create a scratch directory in which to confine the required module

# To make the archive smaller, you can cull unecessary packages and files from the directory. The particulars 
# are beyond the scope of this documentation.

# Create the zip archive and put the required modules in
zip -r9 ./${CODE_ARCHIVE_FILENAME} ./lambda

# Add the egress python code
zip -g ./${CODE_ARCHIVE_FILENAME} ./app.py

# Add the update lambda
zip -g ./${CODE_ARCHIVE_FILENAME} ./update_lambda.py

# Add the html templates
zip -g -r2 ./${CODE_ARCHIVE_FILENAME} ./templates

# Add the common code:
cd rain_api_core
zip -g -r9 ./${CODE_ARCHIVE_FILENAME} ./rain_api_core
cd ..

# Upload to S3
aws s3 cp --profile=default ./${CODE_ARCHIVE_FILENAME} s3://${CODE_BUCKET}/

```


### AWS Secrets

#### Setting up the URS client secrets:
`UrsId` can be found on your SSO application's URS home page as `Client ID`. 

`UrsAuth` is the `UID` for your URS SSO app and password separated by a colon. You can create the value with the command below. See URS' [Request Authorization Code](https://urs.earthdata.nasa.gov/sso_client_impl) documentation for more details.

```bash
echo -n "<UID>:<App Password>" | openssl base64 
```


Put the base-64 encoded keys into a json file like so: 
```json
{
    "UrsId": "<pasted value of Client ID>",
    "UrsAuth": "<pasted value of b64 encoded URS auth>"
}
```

Create the secret in AWS, referencing the json file created above
```bash
aws secretsmanager create-secret --name urs_creds_for_tea \
    --description "URS creds for TEA app" \
    --secret-string file://urscreds.json
```
#### Setting up the JWT Cookie secrets
##### Option 1: Manually
Create a key pair and b64 encode them:
```bash
ssh-keygen -t rsa -b 4096 -m PEM -f ./jwtcookie.key
openssl base64 -in jwtcookie.key -out jwtcookie.key.b64 -A
openssl base64 -in jwtcookie.key.pub -out jwtcookie.key.pub.b64 -A
```
Put the base-64 encoded keys into a json file like so: 
```json
{
    "rsa_priv_key": "<pasted value of b64'd private key>",
    "rsa_pub_key":  "<pasted value of b64'd public key>"
}
```
Create the secret in AWS, referencing the json file created above
```bash
aws secretsmanager create-secret --name jwt_secret_for_tea \
    --description "RS256 keys for TEA app JWT cookies" \
    --secret-string file://jwtkeys.json
```

##### Option 2: Using bash script
You can create an encoded b64 key pair by running the provided [setup_jwt_cookie.sh](https://github.com/asfadmin/thin-egress-app/blob/devel/setup_jwt_cookie.sh) script :
```bash
profile_name=<aws_profile> aws_region=<region> bash setup_jwt_cookie.sh
```


### Buckets and Bucket map

The bucket map allows the app to determine in which bucket to look when given the path from the URL.

If a url for a product would look like:
```https://datapile.domain.com/STAGE/PROCESSING_TYPE_1/PLATFORM_A/datafile.dat```


And if we have a data bucket prefix of `prfx-d-` and our data bucket list looks like this:
```
- prfx-d-imgs
- prfx-d-pa-pt1
- prfx-d-pb-pt1
- prfx-d-pa-pt2
- prfx-d-pb-pt2
- prfx-d-pa-pt3a
- prfx-d-pb-pt3b
- prfx-d-pa-pt3a
- prfx-d-pb-pt3b
- prfx-d-private-x
- prfx-d-private-y

```

A basic bucket map YAML file would look like this:

```yaml
MAP:
  PROCESSING_TYPE_1:
    PLATFORM_A:         pa-pt1
    PLATFORM_B:         pb-pt1
  
  # Custom response headers for the redirect are supported:
  PROCESSING_TYPE_2:
    PLATFORM_A:
      bucket:           pa-pt2
      headers:
        x-custom-header-1: "custom header 1 value"
        x-custom-header-2: "custom header 2 value"
    PLATFORM_B:         
      bucket:           pb-pt2
      headers:
        x-custom-header-1: "custom header 1 value"
        x-custom-header-2: "custom header 2 value"
  
  # arbritary number of "subdirectories" are supported:
  PROCESSING_TYPE_3:
    SUB_PROCESSING_TYPE_3A:
      PLATFORM_A:       pa-pt3a
      PLATFORM_B:       pb-pt3a
    SUB_PROCESSING_TYPE_3B:
      PLATFORM_A:       pa-pt3b
      PLATFORM_B:       pb-pt3b
        
  THUMBNAIL:
    PLATFORM_A:         imgs
    PLATFORM_B:         imgs
    
PUBLIC_BUCKETS:
  imgs: 'BROWSE IMAGERY'

PRIVATE_BUCKETS:
  pa-pt1:
  - urs_group_name_0
  pa-pt2:
  - urs_group_name_1

```

Given this bucketmap and a bucket prefix of `prfx-d-`: 
* A URL like `http://domain.com/PROCESSING_TYPE_1/PLATFORM_A/file.dat` would cause TEA to look for `file.dat` in a bucket named `prfx-d-pa-pt1`. Additionally, because that bucket is listed in the `PRIVATE_BUCKETS` section, it will only be available to users belonging to a URS group named `urs_group_name_0`.
* A URL like `http://domain.com/PROCESSING_TYPE_2/PLATFORM_A/file.dat` would cause TEA to look for `file.dat` in a bucket named `prfx-d-pa-pt2`. It will send response headers defined in that section with the redirect. 
* A URL like `http://domain.com/THUMBNAIL/PLATFORM_A/file.dat` would cause TEA to look for `file.dat` in a bucket named `prfx-d-imgs`. Because `imgs` is listed under `PUBLIC_BUCKETS`, the file would be public and available to all.


### Config bucket
You will need a bucket for config and optionally the html templates. This should be in the same region as the stack.

### HTML templates 
You may optionally create your own [jinja2](http://jinja.pocoo.org/docs/2.10/) html templates.

#### Option 1: Using custom templates
After you've created your custom templates, create a subdirectory in your `ConfigBucket` and upload them there. Since the lambda downloads the files in this directory to itself, it's best to put only your template files here. When you deploy your CF, enter this directory name into the `HtmlTemplateDir` param.  

#### Option 2: Using default templates
When deploying the CF, set `HtmlTemplateDir` to '' (empty string).

#### The templates

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

### Cloudformation parameters
It's best to look at the parameter section of the [Cloudformation template](https://github.com/asfadmin/thin-egress-app/blob/master/cloudformation/thin-egress-app.yaml) itself to get the most up to date details.

### Deploying the app in NGAP (option)

To deploy into NGAP, there are a few extra params. Check the `NGAP Integration` section of the CloudFormation Template.

Use the following bash script to determine appropriate compliance paramaters.

```bash
export AWS_REGION='us-west-2'
export AWS_PROFILE='default'
export AWSENV="--profile=${AWS_PROFILE} --region=${AWS_REGION}"
export VPCID=$(aws $AWSENV ec2 describe-vpcs --query "Vpcs[*].VpcId" --filters "Name=tag:Name,Values=Application VPC" --output text)
export SUBNETID=$(aws $AWSENV ec2 describe-subnets --query "Subnets[?VpcId=='$VPCID'].{ID:SubnetId}[0]" --filters "Name=tag:Name,Values=Private*" --output=text)
export SECURITYGROUP=$(aws $AWSENV ec2 describe-security-groups --query "SecurityGroups[?VpcId=='$VPCID'].{ID:GroupId}" --filters "Name=tag:Name,Values=Application Default*" --output=text)
echo "PrivateVPC=$VPCID; VPCSecurityGroupIDs=$SECURITYGROUP; VPCSubnetIDs=$SUBNETID;"


# Its also important to be aware that if an API Gateway VPC Endpoint will need to setup prior to deployment. You can check to see if your account has the appropriate VPCE by runing this command:
aws $AWSENV ec2 describe-vpc-endpoints --query "VpcEndpoints[?(VpcId=='$VPCID' && ServiceName=='com.amazonaws.us-east-1.execute-api')].{ID:VpcEndpointId}" --output=text
```

If you get a return value like `vpce-0123456789abcdef0`, you're good to go, proceed to the "Deploying the app" section below. 

### Deploying the app
The easiest way to deploy a Thin Egress App is by using one of the YAML files in [ASF's public code bucket](https://s3.amazonaws.com/asf.public.code/index.html). Download the YAML for the build you want, the values for `LambdaCodeS3Bucket` and `LambdaCodeS3Key` will have default values for deploying that build's lambda code. Some of the vars set below duplicate those in the NGAP procedure above, be sure to not overwrite the correct values if you're cutting and pasting from here.

```bash
# Set some vars
CF_TEMPLATE_FILE=/absolute/path/to/tea-cloudformation-build.XX.yaml

# See the Cloudformation parameters section above for a description of these params.
STACK_NAME=my-tea # needs to be compatible with S3 naming requirements (lower case, no underscores, etc) 
                  # because the CF template may create buckets using this name.
AWS_REGION=us-west-2 # Or another region if desired.
AWS_PROFILE=default  # Or whichever aws cli profile gives you the write access necessary.

BUCKETMAP_FILENAME=my_bucketmap.yaml
BUCKET_PREFIX=asf-tea-
CFG_BUCKETNAME=asf-tea-cfg

# Set these three to empty string if no domain is to be used. 
DOMAIN_NAME=a-domain.something.tld 
COOKIE_DOMAIN=.something.tld
DOMAINCERTARN=arn:aws:acm:us-east-1:000000000000:certificate/00000000-0000-0000-0000-000000000000

# Use these if your data buckets are in a different region than 
# your TEA stack. Set to empty string otherwise
DOWNLOAD_ROLE_ARN=arn:aws:iam::000000000000:role/AccessToFiles
DOWNLOAD_ROLE_ARN_INREGION=arn:aws:iam::000000000000:role/AccessToFilesInRegion 

# If using the generic, default templates included with the Lambda, set to empty string. 
HTML_TEMPLATE_DIR=html 

JWTALGO=RS256
JWTKEYSECRETNAME=jwt_secret_for_tea

# CODE_BUCKET must be in same region as this stack.
# Omit CODE_BUCKET if using build-specific YAML from ASF's public code bucket
CODE_BUCKET=asf.public.code
CODE_DIR=thin-egress-app
DEPENDENCYLAYERFILENAME=tea-dependencylayer.zip
CODE_ARCHIVE_FILENAME=tea-code.zip
URS_CREDS_SECRET_NAME=urs_creds_for_tea

# Deploy the stack
aws cloudformation deploy --profile=${AWS_PROFILE} --region=${AWS_REGION} \
  --stack-name ${STACK_NAME} \
  --template-file ${CF_TEMPLATE_FILE} \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
        AuthBaseUrl=https://urs.earthdata.nasa.gov \
        BucketMapFile=${BUCKETMAP_FILENAME} \
        BucketnamePrefix=${BUCKET_PREFIX} \
        ConfigBucket=${CFG_BUCKETNAME} \
        CookieDomain=${COOKIE_DOMAIN} \
        DomainCertArn=${DOMAINCERTARN}  \
        DomainName=${DOMAIN_NAME} \
        DownloadRoleArn=${DOWNLOAD_ROLE_ARN} \
        DownloadRoleInRegionArn=${DOWNLOAD_ROLE_ARN_INREGION} \
        EnableApiGatewayLogToCloudWatch="False" \ 
        HtmlTemplateDir=${HTML_TEMPLATE_DIR} \
        JwtAlgo=${JWTALGO} \
        JwtKeySecretName=${JWTKEYSECRETNAME} \
        LambdaCodeDependencyArchive=${CODE_DIR}/${DEPENDENCYLAYERFILENAME} \
        LambdaCodeS3Bucket=${CODE_BUCKET} \
        LambdaCodeS3Key=${CODE_DIR}/${CODE_ARCHIVE_FILENAME} \
        LambdaTimeout=6 \
        Loglevel=INFO \
        Maturity=DEV \
        PermissionsBoundaryName= \
        PrivateBucketsFile= \
        PublicBucketsFile= \
        PrivateVPC= \
        SessionTTL=168 \
        StageName=API \
        URSAuthCredsSecretName=${URS_CREDS_SECRET_NAME} \
        UseReverseBucketMap="False" 
        VPCSecurityGroupIDs= \
        VPCSubnetIDs= 

```
### Post-deploy action
After the Cloudformation has been deployed, we need to add the new endpoint to the URS Redirect URI list. Get the necessary value like so:


Add it here: `https://urs.earthdata.nasa.gov/apps/<NAME OF YOUR URS APP>/redirect_uris`

Now you can go to the API Endpoint and test login. API endpoint can be retrieved with this command:
```bash
aws cloudformation --region=${AWS_REGION} --profile=${AWS_PROFILE} describe-stacks --stack-name=${STACK_NAME} --query 'Stacks[0].Outputs[?OutputKey==`ExternalEndpoint`].OutputValue' --output text
```



## Cookies / JWT

TEA now uses JWT cookies. 

#### JWT cookie
The JWT cookie's default name is `asf-urs` It contains various information about the logged in user.

Its payload looks something like this:
```json
{
  "urs-user-id": "<User's URS ID>",
  "urs-access-token": "<A URS access token string>",
  "urs-groups": [
    {
      "app_uid": "<UID of URS app #1>",
      "client_id": "<Client ID string #1>",
      "name": "<Name of group #1>"
    },
    {
      "app_uid": "<UID of URS app #2>",
      "client_id": "<Client ID string #2>",
      "name": "<Name of group #2>"
    }
  ],
  "iat": 1565294120,
  "exp": 1565299000
}

```

## Service chaining with Shared Tokens

![TEA](https://github.com/asfadmin/thin-egress-app/blob/devel/harmony-chain.png)

#### TEA can accept a shared EDL Token as an Authorization (Bearer Token) method
To enable this behavior, EDL Apps (Service + TEA) must belong to a shared EDL App Group. Processing a shared token is temporally expensive. After the initial request, subsequent Service->TEA data requests should reuse cookies. EULA enforcement is preserved in with shared tokens. 

## Troubleshooting.
Something went wrong. Here are some solutions:

### Deploy failures: 

#### Error message: 
If you see an error message in the Cloudformation Events like this: 
> CloudWatch Logs role ARN must be set in account settings to enable logging (Service: AmazonApiGateway; Status Code: 400; Error Code: BadRequestException; ...

#### Solution:

`EnableApiGatewayLogToCloudWatch` is set to `True`. If you don't need API Gateway logging to cloudwatch, set to `False`. If you do, you must create a role with write access to Cloudwatch Logs and add its ARN here: https://console.aws.amazon.com/apigateway/home?region=<REGION>#/settings
