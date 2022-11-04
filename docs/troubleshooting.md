# Troubleshooting

## When things go wrong

There is a lot that _can_ go wrong, but we hope that if you followed this
guide, you'll have prevented many of the common problems. If not, start
here!

### Error message:
If you see an error message in the Cloudformation Events like this:
> CloudWatch Logs role ARN must be set in account settings to enable logging (Service: AmazonApiGateway; Status Code: 400; Error Code: BadRequestException; ...

### Solution:

`EnableApiGatewayLogToCloudWatch` is set to `True`. If you don't need API Gateway logging to cloudwatch, set to `False`. If you do, you must create a role with write access to Cloudwatch Logs and add its ARN here: `https://console.aws.amazon.com/apigateway/home?region=<REGION>#/settings`.

### Updating Cached Values:

For efficiency, TEA will cache configuration into the Lambda run environment.
Certain changes, like modifications to the bucket map or secrets, may not be
immediately picked up. Lambda run times will eventually time out, but you can
force refetching of cached values be simply adding a dummy environment
variable to the running Lambda environment. There may be a better way to
trigger Lambda environment flushing, lets us know if you find a way.

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

## Bug reporting/tracking

First step when you encounter an error is to check the
[Troubleshooting](troubleshooting.md) section. If your problem is not there,
feel free to reach out in the `#tea-pot` Slack Channel. If your problem
can't be resolved, we'll put in a
[Github Issue](https://github.com/asfadmin/thin-egress-app/issues) to help
track the problem and seek resolution.
