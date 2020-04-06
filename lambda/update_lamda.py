import json
import boto3
import urllib.request
import os


def lambda_handler(event, context):
    # Get current region
    session = boto3.session.Session()
    current_region = session.region_name

    print(f"Current reigon in {current_region}")
    cidr_list = get_region_cidrs(current_region)

    # Get the base policy and add IP list as a conidtion
    new_policy = get_base_policy(os.getenv("prefix"))
    new_policy["Statement"][0]["Condition"] = {"IpAddress": {"aws:SourceIp": cidr_list}}

    client = boto3.client('iam')
    response = client.put_role_policy(RoleName=os.getenv('iam_role_name'), PolicyName=os.getenv('policy_name'),
                                      PolicyDocument=json.dumps(new_policy))

    return response


def get_region_cidrs(current_region):
    output = urllib.request.urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json').read().decode('utf-8')
    ip_ranges = json.loads(output)['prefixes']
    in_region_amazon_ips = [item['ip_prefix'] for item in ip_ranges if
                            item["service"] == "AMAZON" and item["region"] == current_region]
    return (in_region_amazon_ips)


def get_base_policy(prefix):
    policy = """

    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetObject",
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::{prefix}-*/*",
                "arn:aws:s3:::{prefix}-*"
            ],
            "Effect": "Allow"
        }
    ]
}

    """

    return json.loads(policy)
