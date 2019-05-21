# TEA (Thin Egress App)
## About
The Thin Egress App is an app running in lambda that creates temporary S3 links and provides URS integration.

![Last Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Fbuildstatus.json)
![Test Results](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Ftestresults.json)
![Last Build](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastbuild.json)
![Last Good Build](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastgoodbuild.json)
![Last Release](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastrelease.json)

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
* An [IAM Role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) the lambda can assume to read the files in the data buckets.

### Using pre-packaged lambda code

Pre-packaged versions of the lambda code and associated cloudformation YAML are in S3 in [ASF's public code bucket](https://s3.amazonaws.com/asf.public.code/index.html). To use this, download the YAML for the build you want and deploy it. The correct lambda zipfile will be the default.

### Packaging lambda code
If you prefer to roll your own zip for the lambda code:
```bash 
# Make up a filename for code archive:
CODE_ARCHIVE_FILENAME=thin-egress-app-code.zip

# get the repo
git clone https://github.com/asfadmin/thin-egress-app
cd thin-egress-app

# Create a scratch directory in which to confine the required modules
mkdir pkg
cd pkg 

# Install requirements here
pip3 install -r ../lambda/requirements.txt  --target .

# Create the zip archive and put the required modules in
zip -r9 ../${CODE_ARCHIVE_FILENAME} ./*

# Add the egress python code
cd ../lambda
zip -g ../${CODE_ARCHIVE_FILENAME} ./*.py

# Add the html templates
zip -g -r ../${CODE_ARCHIVE_FILENAME} ./templates
cd ..

# Upload to S3
aws s3 cp --profile=default ./${CODE_ARCHIVE_FILENAME} s3://${CODE_BUCKET}/

```

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

#### Using custom templates
After you've created your custom templates, create a subdirectory in your `ConfigBucket` and upload them there. Since the lambda downloads the files in this directory to itself, it's best to put only your template files here. When you deploy your CF, enter this directory name into the `HtmlTemplateDir` param.  

#### Using default templates
When deploying the CF, set `HtmlTemplateDir` to '' (empty string).

#### The templates

**base.html**
This is the base template. 

Blocks: 
 * pagetitle: Gets inserted inside the `<title></title>` element
 * content

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


### Deploying the app
The easiest way to deploy a Thin Egress App is by using one of the YAML files in [ASF's public code bucket](https://s3.amazonaws.com/asf.public.code/index.html). Download the YAML for the build you want, the values for `LambdaCodeS3Bucket` and `LambdaCodeS3Key` will have default values for deploying that build's lambda code.

The `stack-name` needs to be compatible with S3 naming requirements (lower case, no underscores, etc) because the CF template may create buckets using this name.
```bash
aws cloudformation deploy --profile=default --region=us-east-1 \
  --stack-name ${STACK_NAME} \
  --template-file ./egress-lambda.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    URSAuthCredsSecretName=${URS_CREDS_SECRET_NAME} \
    ConfigBucket=${CFG_BUCKETNAME} \
    HtmlTemplateDir=${HTML_TEMPLATE_DIR} \
    BucketnamePrefix=${BUCKET_PREFIX} \
    BucketMapFile=${BUCKETMAP_FILENAME} \
    LambdaCodeS3Bucket=${CODE_BUCKET} \ # Omit this if using build-specific YAML from ASF's public code bucket
    LambdaCodeS3Key=${CODE_ARCHIVE_FILENAME} \ # Omit this if using build-specific YAML from ASF's public code bucket
    DownloadRoleArn=${DOWNLOAD_ROLE_ARN} \
    SessionStore=S3 \
    SessionTTL=168 \
    StageName=${STAGE_NAME} \
    AuthBaseUrl=https://urs.earthdata.nasa.gov \
    Loglevel=DEBUG \
    Maturity=DEV

```
### Post-deploy action
After the Cloudformation has been deployed, we need to add the new endpoint to the URS Redirect URI list. Get the necessary value like so:

```bash
aws cloudformation --region=us-east-1 describe-stacks --stack-name=${STACK_NAME} --query 'Stacks[0].Outputs[?OutputKey==`URSredirectURI`].OutputValue' --output text
```
Add it here: `https://urs.earthdata.nasa.gov/apps/<NAME OF YOUR URS APP>/redirect_uris`
