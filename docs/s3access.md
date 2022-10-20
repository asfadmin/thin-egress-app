## S3 Direct Access
*NOTE: Support for S3 direct access is currently experimental*

You can retrieve temporary S3 credentials at the `/s3credentials` endpoint when
authenticated via earthdata login. These credentials will be valid for 1 hour
and can be used make in-region `s3:ListBucket` and `s3:GetObject` requests.

### Request
Credentials are retrieved through a `GET` request to the `/s3credentials`
endpoint. An optional header `app-name` can be provided to include in the
generated role session name which will show up in EMS logs.

**Params:**
None.

**Headers:**
  - `app-name`: A string to include in the generated role session name for
  metric reporting purposes. It is recommended to include this header when
  making requests on users behalf from another cloud service. The generated
  role session name is `username@app-name`.

**Example:**
```python
import requests

requests.get(
    "https://your-tea-host/s3credentials",
    headers={"app-name": "my-application"},
    cookies={"asf-urs": "<your jwt token>"}
)
```

### Response
The response is your temporary credentials as returned by Amazon STS.
[See the AWS Credentials reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_Credentials.html")

**Example:**
```json
{
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "SessionToken": "LONGSTRINGOFCHARACTERS.../HJLgV91QJFCMlmY8slIEOjrOChLQYmzAqrb5U1ekoQAK6f86HKJFTT2dONzPgmJN9ZvW5DBwt6XUxC9HAQ0LDPEYEwbjGVKkzSNQh/",
  "Expiration": "2021-01-27 00:50:09+00:00"
}
```

### Using Temporary Credentials
To use the credentials you must configure your AWS client with the returned
access key, secret and token. Note that the credentials will only work in-
region, so you will get 403 errors if you try to use them with the AWS cli.

**Example:**
```python
import boto3
import requests

def get_client():
  resp = requests.get(
      "https://your-tea-host/s3credentials",
      headers={"app-name": "my-application"},
      cookies={"asf-urs": "<your jwt token>"}
  )
  resp.raise_for_status()
  creds = resp.json()

  return boto3.client(
      "s3",
      aws_access_key_id=creds["AccessKeyId"],
      aws_secret_access_key=creds["SecretAccessKey"],
      aws_session_token=creds["SessionToken"]
  )

```

### Limits

The credentials dispensed from the `/s3credentials` endpoint are valid for
**1 hour**. Your code must handle expired tokens and request new ones as needed
for sessions that exceed this 1 hour limit. This is an AWS Limit is due to
[role chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html)

These credentials will have `s3:GetObject` and `s3:ListBucket` permissions on
the configured resources.
