import json
import os
import urllib.request

import boto3
import cfnresponse
from netaddr import cidr_merge


def lambda_handler(event, context):
    try:
        # Get current region
        session = boto3.session.Session()
        current_region = session.region_name
        client = boto3.client('iam')

        print(f"Current region in {current_region}")
        cidr_list = get_region_cidrs(current_region)

        # Get the base policy and add IP list as a condition
        new_policy = get_base_policy(os.getenv("prefix"))
        new_policy["Statement"][0]["Condition"] = {"IpAddress": {"aws:SourceIp": cidr_list}}

        # Clear out any pre-existing roles:
        RoleName = os.getenv('iam_role_name')
        response = client.list_role_policies(RoleName=RoleName)
        if 'PolicyNames' in response:
            for PolicyName in response['PolicyNames']:
                print(f"Removing old Policy {PolicyName} from Role {RoleName}")
                response = client.delete_role_policy(RoleName=RoleName, PolicyName=PolicyName)

        # Put the new policy
        response = client.put_role_policy(RoleName=RoleName, PolicyName=os.getenv('policy_name'),
                                          PolicyDocument=json.dumps(new_policy))

        # Check if response is coming from CloudFormation
        if 'ResponseURL' in event:
            print("Sending success message to callback URL {0}".format(event['ResponseURL']))
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {'Data': "Good"})

        return response

    except Exception as e:
        error_string = "There was a problem updating policy {0} for Role {1} in region {2}: {3}".format(
            os.getenv('policy_name'), os.getenv('iam_role_name'), current_region, e)
        print(error_string)

        if 'ResponseURL' in event:
            print("Sending FAILURE message to callback URL {0}".format(event['ResponseURL']))
            cfnresponse.send(event, context, cfnresponse.FAILED, {'Data': error_string})

    return False


def get_region_cidrs(current_region):
    # Bandit complains with B310 on the line below. We know the URL, this is safe!
    output = urllib.request.urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json').read().decode('utf-8')  # nosec
    ip_ranges = json.loads(output)['prefixes']
    in_region_amazon_ips = [item['ip_prefix'] for item in ip_ranges if
                            item["service"] == "AMAZON" and item["region"] == current_region]
    # It's important to filter down the CIDR range as much as possible. Too large can cause the role creation to fail.
    in_region_amazon_ips = [str(ip) for ip in cidr_merge(in_region_amazon_ips)]
    # Add in Private IP Space
    in_region_amazon_ips.append('10.0.0.0/8')
    return in_region_amazon_ips


def get_base_policy(prefix):
    vpcid = os.getenv('vpcid')
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:GetBucketLocation"
                ],
                "Resource": [
                    f"arn:aws:s3:::{prefix}*/*",
                    f"arn:aws:s3:::{prefix}*"
                ],
                "Effect": "Allow"
            },
            {
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:GetBucketLocation"
                ],
                "Resource": [
                    f"arn:aws:s3:::{prefix}*/*",
                    f"arn:aws:s3:::{prefix}*"
                ],
                "Effect": "Allow",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceVpc": f"{vpcid}"
                    }
                }
            },
            {
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:GetBucketLocation"
                ],
                "Resource": [
                    f"arn:aws:s3:::{prefix}*/*",
                    f"arn:aws:s3:::{prefix}*"
                ],
                "Effect": "Allow",
                "Condition": {
                    "StringLike": {
                        "aws:SourceVpc": "vpc-*"
                    }
                }
            }
        ]
    }
