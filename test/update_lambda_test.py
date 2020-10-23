import json
import logging
import unittest

from .. import update_lambda

logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)
logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)
logging.getLogger('nose').setLevel(logging.ERROR)
logging.getLogger('elasticsearch').setLevel(logging.ERROR)
logging.getLogger('s3transfer').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger('connectionpool').setLevel(logging.ERROR)

logging.basicConfig(format='%(asctime)s [L%(lineno)s - %(funcName)s()]: %(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)



class update_lambda_test(unittest.TestCase):


    def test_get_base_policy(self):
        prefix = "prefix-test"
        Json_loaded_Obj= update_lambda.get_base_policy(prefix)
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
        self.assertEquals(json.load(policy),Json_loaded_Obj)


if __name__ == '__main__':
    unittest.main()