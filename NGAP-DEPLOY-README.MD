# Deploying Thin Egress to NGAP

### ⚠️ If you're deploying from Cumulus, most or all of this provided for you. Please consult current Cumulus Documentation ⚠️

Cumulus provides a baseline Bucket Map, but its often desirable to overwrite that bucket map with one that fits your particular and evolving deployment, data structure, and DAAC needs. For more information on creating a bucket map file, see the [**Create A Bucket Map**](https://github.com/asfadmin/thin-egress-app/blob/main/NGAP-DEPLOY-README.MD#create-a-bucket-map-file) Section below. 

### Using Terraform to deploy TEA

The Thin Egress App is available as a [Terraform module](https://www.terraform.io/docs/configuration/modules.html). It can be added to your Terraform configuration using a `module` block.

The latest version of TEA and the Terrafrom module can be found at
[https://s3.amazonaws.com/asf.public.code/index.html](https://s3.amazonaws.com/asf.public.code/index.html). The below guide is intended to be a step-by-step set of instructions for deploying TEA into NGAP.

As of this writing, the lastest module source is
`https://s3.amazonaws.com/asf.public.code/thin-egress-app/tea-terraform-build.74.zip`, The latest released version is ![Last Release](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastrelease.json)

```hcl
# Example Thin Egress App configuration

module "thin_egress_app" {
  source = "https://s3.amazonaws.com/asf.public.code/thin-egress-app/tea-terraform-build.74.zip"

  bucketname_prefix          = ""
  config_bucket              = "my-config-bucket"
  stack_name                 = "my-tea-stack"
  urs_auth_creds_secret_name = "my-secret-location"
}
```



## Input variables

### Required

* **bucketname_prefix** (string) - all data buckets should have names prefixed with this. Must be compatible with S3 naming conventions (lower case only, etc). An empty string can be used to indicate no prefix
* **config_bucket** (string) - the bucket where config files can be found
* **jwt_secret_name** (string) - name of AWS secret where keys for JWT encode/decode are stored
* **stack_name** (string) - the name of the Thin Egress App CloudFormation stack
* **urs_auth_creds_secret_name** (string) - AWS Secrets Manager name of URS creds. Must consist of two rows, names 'UrsId' and 'UrsAuth'

### Optional

* **auth_base_url** (string) - the 'AUTH_BASE_URL' env var in the lambda. Defaults to "https://urs.earthdata.nasa.gov".
* **bucket_map_file** (string) - path and file of bucketmap file's location in the config_bucket. Defaults to "bucket_map.yaml".
* **domain_name** (string) - custom domain name used by redirect_url
* **download_role_arn** (string) - ARN for reading of data buckets
* **html_template_dir** (string) - directory in ConfigBucket where the lambda will look for html templates. Lambda will not look into subdirectories. Please put only html templates in this dir. Leave this field blank to use default templates that are included with the lambda code zip file.
* **jwt_algo** (string) - Algorithm with which to encode the JWT cookie. Defautls to "RS256"
* **lambda_code_s3_bucket** (string) - S3 bucket of packaged lambda egress code. Defaults to "asf.public.code"
* **lambda_code_s3_key** (string) - S3 key of packaged lambda egress code. Defaults to "thin-egress-app/tea-code-<BUILD_ID>.zip", where "BUILD_ID" is determined when the Terraform module was pacakged.
* **log_level** (string) - Python loglevel. Defaults to "DEBUG"
* **maturity** (string) - maturity of deployment. Defaults to "DEV".
* **permissions_boundary_name** (string) - PermissionsBoundary Policy name to be used when creating IAM roles
* **private_vpc** (string) - internal VPC to deploy to
* **session_ttl** (number) - time to live for auth session, in hours. Defaults to 168.
* **stage_name** (string) - this value will show up as the base of the url path as so: `https://xxxxxxxx.execute-api.us-east-1.amazonaws.com/<StageName>/and/so/on`. Defaults to "API".
* **use_reverse_bucket_map** (bool) - standard bucketmaps are not reverse. Defaults to false.
* **vpc_security_group_ids** (list(string)) - list of security groups for the Lambda function
* **vpc_subnet_ids** (list(string)) - list of subnets for the lambda function

## Output variables

* **api_endpoint** (string) - the API Gateway endpoint of the deployment
* **urs_redirect_uri** (string) - the URS redirect URI to be configured for the app in Earthdata Login
* **egress_log_group** (string) - API Gateway Access logs LogGroup, if enabled

## Pre-deployment configuration steps

### Create a bucket map file

In the example below, `bucketname_prefix` is `data-ingest-dev-`, so `public` maps to `data-ingest-dev-public`. If you have not supplied a prefix, you can instead use the full bucket name. Use a prefix can be desirable as it allows bucket maps to potentially be viable across maturies and projects

Data in s3://data-ingest-dev-public will be addressable at https://endpoint/DATA/BROWSE/{object}

```shell
cat > /tmp/bucket_map.yaml <<EOS
MAP:
  DATA:
    BROWSE:   public
    SLC:      protected
    GRD:      protected
    METADATA: protected

PUBLIC_BUCKETS:
  - public
EOS
```

Data in the `protected` (aka `s3://data-ingest-dev-protected`) bucket will require URS Authentication to access.

For more info on constructing a bucket Mmp, see [Buckets and Bucket Map](https://github.com/asfadmin/thin-egress-app#buckets-and-bucket-map)

### Upload bucket map to internal/config bucket

```shell
aws s3 $AWSENV cp /tmp/bucket_map.yaml s3://<your_config_bucket>/bucket_map.yaml
```

### Create URS Credentials And JWT Secrets:

You will need to provide your URS App credentails (`urs_auth_creds_secret_name`) and the JWT Cookie Keys (`jwt_secret_name`) as AWS Screts Manager items.

See [AWS Secrets](https://github.com/asfadmin/thin-egress-app/#aws-secrets) for more information.  

### Update URS redirect_uri:

The TEA Terraform module has the output value `urs_redirect_uri`. This URL should be added to your URS App as a valid Redirect URI. If updating the app to supply CloudFront URL or Custom DNS records using the `domain_name` and `cookie_domain` fields, it will be important to update or replace the output `urs_redirect_uri` value in your URS App.
