# S3 Direct Access

You can retrieve temporary S3 credentials at the `/s3credentials` endpoint when
authenticated via Earthdata Login. These credentials will only be valid for
**1 hour** due to
[role chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html)
and can be used make in-region `s3:ListBucket` and `s3:GetObject` requests.
Your code must handle expired tokens and request new ones as needed
for sessions that exceed this 1 hour limit.

## Request

Credentials are retrieved through an HTTP `GET` request to the `/s3credentials`
endpoint. The request must be authenticated with either a JWT token for TEA or
by using
[EDL Bearer Tokens](https://urs.earthdata.nasa.gov/documentation/for_users/user_token).
Unauthenticated requests will be redirected to EDL.

**Headers:**

* (optional) `app-name`: An arbitrary string to include in the generated role
  session name for metric reporting purposes. It can only contain characters
  that are valid in a `RoleSessionName` see the
  [AssumeRole documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_RequestParameters).
  It is recommended to include this header when making requests on users behalf
  from another cloud service. The generated role session name is
  `username@app-name`.

**Example:**
```python
import requests

resp = requests.get(
    "https://your-tea-host/s3credentials",
    headers={"app-name": "my-application"},
    cookies={"asf-urs": "<your jwt token>"}
)
print(resp.json())
```

## Response

The response is your temporary credentials as returned by Amazon STS. See the
[AWS Credentials reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_Credentials.html) for more details.

**Example:**
```json
{
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "sessionToken": "LONGSTRINGOFCHARACTERS.../HJLgV91QJFCMlmY8slIEOjrOChLQYmzAqrb5U1ekoQAK6f86HKJFTT2dONzPgmJN9ZvW5DBwt6XUxC9HAQ0LDPEYEwbjGVKkzSNQh/",
    "expiration": "2021-01-27 00:50:09+00:00"
}
```

## Using Temporary Credentials

To use the credentials you must configure your AWS SDK library with the
returned access key, secret and token. Note that the credentials are only valid
for in-region requests, so using them with your AWS CLI will not work! You must
make your requests from an AWS service such as Lambda or EC2 in the same region
as the source bucket you are pulling from. See
[Using temporary credentials with AWS resources](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html)
for more information on how to use your temporary credentials.

### Multipart Chunksize

The AWS `multipart_chunksize` is 8MB by default. It is recommended to increase this to between 128MB-1GB as shown in the example below. Additional resources can be found in the [AWS documentation](https://docs.aws.amazon.com/cli/latest/topic/s3-config.html#configuration-values).

**Example:**

This example lambda function uses
[EDL Bearer Tokens](https://urs.earthdata.nasa.gov/documentation/for_users/user_token)
to obtain s3 credentials and stream an object from one bucket to another. The
lambda execution role will need `s3:PutObject` permissions on the destination
bucket.


```python
import boto3
import json
import urllib.request

MB = 1000 ** 2

def lambda_handler(event, context):
    # Get temporary download credentials
    tea_url = event["CredentialsEndpoint"]
    bearer_token = event["BearerToken"]
    req = urllib.request.Request(
        url=tea_url,
        headers={"Authorization": f"Bearer {bearer_token}"}
    )
    with urllib.request.urlopen(req) as f:
        creds = json.loads(f.read().decode())

    # Set up separate boto3 clients for download and upload
    download_client = boto3.client(
        "s3",
        aws_access_key_id=creds["accessKeyId"],
        aws_secret_access_key=creds["secretAccessKey"],
        aws_session_token=creds["sessionToken"],
    )
    # Lambda needs to have permission to upload to destination bucket
    upload_client = boto3.client("s3")

    # Set up transfer config object
    transfer_config = {
        multipart_chunksize = 128 * MB
    }

    # Stream from the source bucket to the destination bucket
    resp = download_client.get_object(
        Bucket=event["Source"]["Bucket"],
        Key=event["Source"]["Key"],
    )
    upload_client.upload_fileobj(
        Fileobj=resp["Body"],
        Bucket=event["Dest"]["Bucket"],
        Key=event["Dest"].get("Key") or event["Source"]["Key"],
        Config=transfer_config,
    )
```

The example can be invoked with an event payload as follows:

```json
{
    "CredentialsEndpoint": "https://your-tea-host/s3credentials",
    "BearerToken": "your bearer token",
    "Source": {
        "Bucket": "S3 bucket name from CMR link",
        "Key": "S3 key from CMR link"
    },
    "Dest": {
        "Bucket": "S3 bucket name to copy to"
    }
}
```
