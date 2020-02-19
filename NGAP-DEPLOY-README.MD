# Deploying Thin Egress to NGAP

The Thin Egress App is available as a [Terraform module](https://www.terraform.io/docs/configuration/modules.html). It can be added to your Terraform configuration using a `module` block. If your deployment does not yet use Terraform, [these instructions](https://nasa.github.io/cumulus/docs/deployment/components) should prove useful.

The lastest version of the module can be found at
[https://s3.amazonaws.com/asf.public.code/index.html](https://s3.amazonaws.com/asf.public.code/index.html).

As of this writing, the lastest module source is
`https://s3.amazonaws.com/asf.public.code/thin-egress-app/tea-terraform-build.16.zip`.

```hcl
# Example Thin Egress App configuration

module "thin_egress_app" {
  source = "https://s3.amazonaws.com/asf.public.code/thin-egress-app/tea-terraform-build.16.zip"

  bucketname_prefix          = ""
  config_bucket              = "my-config-bucket"
  stack_name                 = "my-tea-stack"
  urs_auth_creds_secret_name = "my-secret-location"
}
```

## Input variables

### Required

* **bucketname_prefix** (string) - all data buckets should have names prefixed with this. Must be compatible with S3 naming conventions (lower case only, etc). An empty string can be used to indicate no prefix.
* **config_bucket** (string) - the bucket where config files can be found
* **stack_name** (string) - the name of the Thin Egress App CloudFormation stack
* **urs_auth_creds_secret_name** (string) - AWS Secrets Manager name of URS creds. Must consist of two rows, names 'UrsId' and 'UrsAuth'.

### Optional

* **auth_base_url** (string) - the 'AUTH_BASE_URL' env var in the lambda. Defaults to "https://urs.earthdata.nasa.gov".
* **bucket_map_file** (string) - path and file of bucketmap file's location in the ConfigBucket. Defaults to "bucket_map.yaml".
* **domain_name** (string) - custom domain name used by redirect_url
* **download_role_arn** (string) - ARN for reading of data buckets
* **html_template_dir** (string) - directory in ConfigBucket where the lambda will look for html templates. Lambda will not look into subdirectories. Please put only html templates in this dir. Leave this field blank to use default templates that are included with the lambda code zip file.
* **lambda_code_s3_bucket** (string) - S3 bucket of packaged lambda egress code. Defaults to "asf.public.code"
* **lambda_code_s3_key** (string) - S3 key of packaged lambda egress code. Defaults to "thin-egress-app/tea-code-<BUILD_ID>.zip", where "BUILD_ID" is determined when the Terraform module was pacakged.
* **log_level** (string) - Python loglevel. Defaults to "DEBUG"
* **maturity** (string) - maturity of deployment. Defaults to "DEV".
* **permissions_boundary_name** (string) - PermissionsBoundary Policy name to be used when creating IAM roles
* **private_vpc** (string) - internal VPC to deploy to
* **private_buckets_file** (string) - path and file of private buckets file's location in the ConfigBucket
* **public_buckets_file** (string) - path and file of public buckets file's location in the ConfigBucket
* **session_store** (string) - "DB" for storing sessions in DynamoDB, "S3" for storing sessions in S3. Defaults to "DB".
* **session_ttl** (number) - time to live for auth session, in hours. Defaults to 168.
* **stage_name** (string) - this value will show up as the base of the url path as so: `https://xxxxxxxx.execute-api.us-east-1.amazonaws.com/<StageName>/and/so/on`. Defaults to "API".
* **use_reverse_bucket_map** (bool) - standard bucketmaps are not reverse. Defaults to false.
* **vpc_security_group_ids** (list(string)) - list of security groups for the Lambda function
* **vpc_subnet_ids** (list(string)) - list of subnets for the lambda function

## Output variables

* **api_endpoint** (string) - the API Gateway endpoint of the deployment
* **urs_redirect_uri** (string) - the URS redirect URI to be configured for the app in Earthdata Login

## Pre-deployment configuration steps

### Create a bucket map file

Prefix is `sirc-ingest-dev-`, so  `public` maps to `sirc-ingest-dev-public`.

Data in s3://sirc-ingest-dev-public will be addressable at https://endpoint/SIRC/BROWSE/{object}

```shell
cat > /tmp/bucket_map.yaml <<EOS
MAP:
  SIRC:
    BROWSE:   public
    SLC:      protected
    GRD:      protected
    METADATA: protected

PUBLIC_BUCKETS:
  - public
EOS
```

### Upload bucketmap to internal bucket

```shell
aws s3 $AWSENV cp /tmp/bucket_map.yaml s3://sirc-ingest-dev-internal/bucket_map.yaml
```

### Create URS Credentials

```shell
aws secretsmanager create-secret $AWSENV \
  --name tea-urs-creds-dev \
  --secret-string '{"UrsId": "VXJzSWQ=","UrsAuth": "VXJzQXV0aA=="}' \
  --description 'URS Credentials for TEA Distribution App'
```
