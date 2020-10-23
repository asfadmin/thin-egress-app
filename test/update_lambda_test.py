import unittest
from lambdacode import update_lambda
import json







class update_lambda_test(unittest.TestCase):

    #Intergration Test : that the lambda handler given an event returns the correct response from cloudformation
    def test_lambda_handler(self):
        unittest.TextTestRunner().run(
            unittest.TestLoader().loadTestsFromTestCase(MyTest))

    #Using us-west-2  ensure the method has the correct region id in its list
    def test_get_region_cidrs(self):
        current_region = "us-west-2"
        self.assertTrue(update_lambda.get_region_cidrs(current_region).count('52.94.76.0/22') > 0 )

    #Check that the base policy is allowing the prefix to be added
    def test_get_base_policy(self):
        prefix = "prefix-test"
        base_policy = update_lambda.get_base_policy('prefix-test')
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
        self.assertEqual(base_policy,json.loads(policy))

class MyTest(unittest.TestCase):
    def return_type(self,event, context):
        self.assertTrue(isinstance(
            update_lambda.lambda_handler(event, context),int))

if __name__ == '__main__':
    unittest.main()