# TEA (Thin Egress App)
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
* A secret in the [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/managing-secrets.html) containing URS client ID and auth
  * This secret should have two rows, one with key `UrsId` and the other `UrsAuth`
* A bucket map yaml file in a config bucket
* The buckets described in the bucket map must exist. 
  * These need not be in the same account as the egress app.
  * It would help if there were some data in them.

Optional:
* A domain name and SSL cert for the service.
* An [IAM Role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) the lambda can assume to read the files in the data buckets. One will be created if not provided.
* An IAM Role that allows for only in-region access the lambda can assume to read the files in the data buckets. One will be created if not provided.


### Getting the software

#### Option 1: Using pre-packaged lambda code

Pre-packaged versions of the lambda code and associated cloudformation YAML are in S3 in [ASF's public code bucket](https://s3.amazonaws.com/asf.public.code/index.html). To use this, download the YAML for the build you want and deploy it. The correct lambda zipfile will be the default.


#### Option 2: Packaging lambda code yourself

If you prefer to roll your own zip for the lambda code:

#### Dependency Layer
We've found that the if the dependency layer isn't built in an `amazonlinux` environment, the JWT crypto doesn't work. Here are instructions for gathering and packaging the dependencies in an `amazonlinux` docker container.
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

# Add the html templates
zip -g -r2 ./${CODE_ARCHIVE_FILENAME} ./templates

# Add the common code:
cd rain_api_core
zip -g -r9 ./${CODE_ARCHIVE_FILENAME} ./rain_api_core
cd ..

# Upload to S3
aws s3 cp --profile=default ./${CODE_ARCHIVE_FILENAME} s3://${CODE_BUCKET}/

```

## Cookies / JWT

TEA now uses JWT cookies. 
### Cookies
When logging in, rain-api-core sets a few cookies:

#### JWT cookie
The JWT cookie's default name is `asf-urs` It contains various information about the logged in user. New development should use this cookie.

Its payload looks something like this:
```json
{
  "urs-user-id": "<User's URS ID>",
  "urs-access-token": "<A URS access token string>",
  "urs-groups": [
    {
      "app_uid": "<UID of URS app>",
      "client_id": "<Client ID string>",
      "name": "<Name of group>"
    },
    {
      "app_uid": "<UID of URS app>",
      "client_id": "<Client ID string>",
      "name": "<Name of group>"
    }
  ],
  "iat": 1565294120,
  "exp": 1565299000
}

```

#### urs-user-id
This contains the logged in user's URS user ID. This cookie will be deprecated soon, please use the value in the JWT cookie.

#### urs-access-token 
This contains the logged in user's URS access token. This cookie will be deprecated soon, please use the value in the JWT cookie.


### Bucket map

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

```

A basic bucket map YAML file would look like this:

```yaml
MAP:
  PROCESSING_TYPE_1:
    PLATFORM_A:         pa-pt1
    PLATFORM_B:         pb-pt1
  PROCESSING_TYPE_2:
    PLATFORM_A:         pa-pt2
    PLATFORM_B:         pb-pt2
  THUMBNAIL:
    PLATFORM_A:         imgs
    PLATFORM_B:         imgs
    
PUBLIC_BUCKETS:
  - imgs 
```

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
 * `content`

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

### Deployiny the app in NGAP

To deploy into NGAP, there are a few extra params. Check the `NGAP Integration` section of the CloudFormation Template.

Use the following bash script to determine appropriate compliance paramaters.

```bash
export AWSENV='--profile=cumulus --region=us-east-1'
export VPCID=$(aws $AWSENV ec2 describe-vpcs --query "Vpcs[*].VpcId" --filters "Name=tag:Name,Values=Application VPC" --output text)
export SUBNETID=$(aws $AWSENV ec2 describe-subnets --query "Subnets[?VpcId=='$VPCID'].{ID:SubnetId}[0]" --filters "Name=tag:Name,Values=Private*" --output=text)
export SECURITYGROUP=$(aws $AWSENV ec2 describe-security-groups --query "SecurityGroups[?VpcId=='$VPCID'].{ID:GroupId}" --filters "Name=tag:Name,Values=Application Default*" --output=text)
echo "PrivateVPC=$VPCID; VPCSecurityGroupIDs=$SECURITYGROUP; VPCSubnetIDs=$SUBNETID;"
```

Its also important to be aware that if an API Gateway VPC Endpoint will need to setup prior to deployment. You can check to see if your account has the appropriate VPCE by runing this command:

```
aws $AWSENV ec2 describe-vpc-endpoints --query "VpcEndpoints[?(VpcId=='$VPCID' && ServiceName=='com.amazonaws.us-east-1.execute-api')].{ID:VpcEndpointId}" --output=text
```

Keep in mind, if you're not in **US-EAST-1**, you'll need to change that value above. If you get a return value like `vpce-0123456789abcdef0`, you're good to go. 

### Deploying the app
The easiest way to deploy a Thin Egress App is by using one of the YAML files in [ASF's public code bucket](https://s3.amazonaws.com/asf.public.code/index.html). Download the YAML for the build you want, the values for `LambdaCodeS3Bucket` and `LambdaCodeS3Key` will have default values for deploying that build's lambda code.

```bash
# Set some vars
# See the Cloudformation parameters section above for a description of these params.
STACK_NAME=my-tea # needs to be compatible with S3 naming requirements (lower case, no underscores, etc) 
                  # because the CF template may create buckets using this name.
BUCKETMAP_FILENAME=my_bucketmap.yaml
BUCKET_PREFIX=asf-tea-
CFG_BUCKETNAME=asf-tea-cfg
COOKIE_DOMAIN=.asf.alaska.edu
DOMAINCERTARN=arn:aws:acm:us-east-1:000000000000:certificate/00000000-0000-0000-0000-000000000000
DOMAIN_NAME=filedownloads.asf.alaska.edu
DOWNLOAD_ROLE_ARN=arn:aws:iam::000000000000:role/AccessToFiles
DOWNLOAD_ROLE_ARN_INREGION=arn:aws:iam::000000000000:role/AccessToFilesInRegion
HTML_TEMPLATE_DIR=html # Omit if using default templates.
JWTALGO=RS256
JWTKEYSECRETNAME=jwt_secret_for_tea
CODE_BUCKET=code-bucket # Omit this if using build-specific YAML from ASF's public code bucket
CODE_DIR=code-dir
DEPENDENCYLAYERFILENAME=tea-dependencylayer.zip
CODE_ARCHIVE_FILENAME=tea-code.zip
URS_CREDS_SECRET_NAME=urs_creds_for_tea

# Deploy the stack
aws cloudformation deploy --profile=default --region=us-east-1 \
  --stack-name ${STACK_NAME} \
  --template-file ./egress-lambda.yaml \
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
        EnableApiGatewayLogToCloudWatch=True \ # Valid values are "True" and "False" (default)
        HtmlTemplateDir=${HTML_TEMPLATE_DIR} \
        JwtAlgo=${JWTALGO} \
        JwtKeySecretName=${JWTKEYSECRETNAME} \
        LambdaCodeDependencyArchive=${CODE_DIR}/${DEPENDENCYLAYERFILENAME} \
        LambdaCodeS3Bucket=${CODE_BUCKET} \ 
        LambdaCodeS3Key=${CODE_DIR}/${CODE_ARCHIVE_FILENAME} \
        LambdaTimeout=6 \
        Loglevel=DEBUG \
        Maturity=DEV
        PermissionsBoundaryName= \
        PrivateBucketsFile=private_buckets_TEA.yaml \
        PrivateVPC= \
        PublicBucketsFile=public_buckets_TEA.yaml \
        SessionStore=S3 \
        SessionTTL=168 \
        StageName=API \
        URSAuthCredsSecretName=${URS_CREDS_SECRET_NAME} \
        UseReverseBucketMap="False" # Valid values are "True" and "False"
        VPCSecurityGroupIDs= \
        VPCSubnetIDs= \

```
### Post-deploy action
After the Cloudformation has been deployed, we need to add the new endpoint to the URS Redirect URI list. Get the necessary value like so:

```bash
aws cloudformation --region=us-east-1 describe-stacks --stack-name=${STACK_NAME} --query 'Stacks[0].Outputs[?OutputKey==`URSredirectURI`].OutputValue' --output text
```
Add it here: `https://urs.earthdata.nasa.gov/apps/<NAME OF YOUR URS APP>/redirect_uris`
