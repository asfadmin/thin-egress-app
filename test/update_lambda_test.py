import json
import logging
import unittest
from lambdacode import update_lambda
import cfnresponse
import json
import boto3
import urllib.request
import os






class update_lambda_test(unittest.TestCase):


    def test_lambda_handler(self):
        print(update_lambda.lambda_handler(any, any))

    def test_get_region_cidrs(self):
        current_region = "us-west-2"
        self.assertTrue(update_lambda.get_region_cidrs(current_region).count('52.94.76.0/22') > 0 )

    def test_get_base_policy(self):
        prefix = "prefix-test"
        dict = update_lambda.get_base_policy(prefix)
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
                        """ + f'"arn:aws:s3:::{prefix}' + """*/*",
                        """ + f'"arn:aws:s3:::{prefix}' + """*"
                    ],
                    "Effect": "Allow"
                }
            ]
        }
        
            """
        self.assertEqual(dict,json.loads(policy))


if __name__ == '__main__':
    unittest.main()