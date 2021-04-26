import argparse
import sys
import unittest
import os
import boto3
import requests
from requests.auth import HTTPBasicAuth
import logging
import json
import base64
from datetime import datetime

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

default_stackname = "teatest-jenk-same"
default_region = "us-west-2"
# Set environment variables
STACKNAME = os.getenv("STACKNAME_SAME", default_stackname)
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", default_region)
aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

# Connect to AWS
client = boto3.client('apigateway', region_name=AWS_DEFAULT_REGION, aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key)

# Get EgressGateway Rest API ID from AWS and calculate APIROOT
dict = client.get_rest_apis()
API = None
for item in dict['items']:
    if item['name'] == f"{STACKNAME}-EgressGateway":
        API = item['id']

if not API:
    log.info(f"Could not find API for the given stackname {STACKNAME}")
    exit()

APIHOST = f"{API}.execute-api.{AWS_DEFAULT_REGION}.amazonaws.com"
APIROOT = f"https://{APIHOST}/API"

# Important Objects and strings we'll need for our tests
METADATA_FILE = 'SA/METADATA_GRD_HS/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml'
METADATA_FILE_CH = 'SA/METADATA_GRD_HS_CH/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml'
METADATA_CHECK = '<gco:CharacterString>S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml</gco:CharacterString>'
BROWSE_FILE = 'SA/BROWSE/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.jpg'
OBJ_PREFIX_FILE = 'SA/METADATA_GRD_HS_CH/browse/ALAV2A104483200-OORIRFU_000.png'
MAP_PATHS = sorted(["SA/OCN", "SA/OCN_CH", "SB/OCN", "SB/OCN_CH"])

# Configuration:
default_test_result_bucket = "asf.public.code"
default_test_result_object = "thin-egress-app/testresults.json"
default_locate_bucket = "s1-ocn-1e29d408"
TEST_RESULT_BUCKET = os.getenv("TEST_RESULT_BUCKET", default_test_result_bucket)
TEST_RESULT_OBJECT = os.getenv("TEST_RESULT_OBJECT", default_test_result_object)
LOCATE_BUCKET = os.getenv("LOCATE_BUCKET", default_locate_bucket)

# Global variable we'll use for our tests
cookiejar = []
urs_username = os.getenv("URS_USERNAME")
urs_password = os.getenv("URS_PASSWORD")


def env_var_check():
    is_set = True
    if STACKNAME == default_stackname:
        log.info(f"The environment STACKNAME is set to the default value: {default_stackname}")
    if AWS_DEFAULT_REGION == default_region:
        log.info(f"The environment AWS_DEFAULT_REGION is set to the default value: {default_region}")
    if aws_access_key_id is None:
        log.info("The environment variable AWS_ACCESS_KEY_ID is not set")
        is_set = False
    if aws_secret_access_key is None:
        log.info("The environment variable AWS_SECRET_ACCESS_KEY is not set")
        is_set = False
    if TEST_RESULT_BUCKET == default_test_result_bucket:
        log.info(f"The environment TEST_RESULT_BUCKET is set to the default value: {default_test_result_bucket}")
    if TEST_RESULT_OBJECT == default_test_result_object:
        log.info(f"The environment TEST_RESULT_OBJECT is set to the default value: {default_test_result_object}")
    if LOCATE_BUCKET == default_locate_bucket:
        log.info(f"The environment LOCATE_BUCKET is set to the default value: {default_locate_bucket}")
    if urs_username is None:
        log.info("The environment variable URS_USERNAME is not set")
        is_set = False
    if urs_username is None:
        log.info("The environment variable URS_PASSWORD is not set")
        is_set = False
    return is_set


class unauthed_download_test(unittest.TestCase):
    # Check that public files are returned without auth
    def test_check_that_images_are_public(self):
        url = f'{APIROOT}/{BROWSE_FILE}'
        r = requests.get(url)

        log.info(f'Public Image Test {url} Return Code: {r.status_code} (Expect 200)')
        self.assertTrue(r.status_code == 200)

        if 'Content-Type' in r.headers:
            log.info(f"Public Image Test Content-Type: {r.headers['Content-Type']} (Expect 'image/jpeg')")
        else:
            log.warning(f"Public Image Test Failed to get Content-Type. Headers: {r.headers}")
        self.assertTrue('Content-Type' in r.headers and r.headers['Content-Type'] == 'image/jpeg')

    def test_check_public_obj_prefix(self):
        url = f'{APIROOT}/{OBJ_PREFIX_FILE}'
        r = requests.get(url)

        log.info(f'Public prefix in restricted bucket {url} Return Code: {r.status_code} (Expect 200)')
        self.assertTrue(r.status_code == 200)

    # Check for 404 on bad request
    def test_404_on_bad_request(self):
        url = f"{APIROOT}/bad/url.ext"
        r = requests.get(url)

        log.info(f"Checking that a non-existent file ({url}) returns a 404: r.status_code (Expect 404)")
        self.assertTrue(r.status_code == 404)

    # Check that a bad cookie value causes URS redirect:
    def test_bad_cookie_value_cause_URS_redirect(self):
        url = f"{APIROOT}/{METADATA_FILE}"
        cookies = {'urs_user_id': "badusername", 'urs_access_token': "blah"}

        log.info(f"Attempting to use bad cookies ({cookies}) to access {url}")
        r = requests.get(url, allow_redirects=False)

        log.info(f"Bad cookies should result in a redirect to EDL. r.is_redirect: {r.is_redirect} (Expect True)")
        self.assertTrue(r.is_redirect)


class auth_download_test(unittest.TestCase):
    # Validate that auth process is successful
    def test_auth_process_is_successful(self):
        url = f"{APIROOT}/{METADATA_FILE}"
        global cookiejar

        log.info(f"Hitting {url} to get redirect to URS for auth")
        session = requests.session()
        request = session.get(url)
        url_earthdata = request.url

        secret_password = urs_password[0] + "*" * (len(urs_password) - 2) + urs_password[-1]
        log.info(
            f"Following URS Redirect to {url_earthdata} with Basic auth ({urs_username}/{secret_password}) to generate an access cookie")
        login2 = session.get(url_earthdata, auth=HTTPBasicAuth(urs_username, urs_password))

        log.info(f"Login attempt results in status_code: {login2.status_code}")
        cookiejar = session.cookies

        # Copy .asf.alaska.edu cookies to match API Address
        for z in cookiejar:
            if "asf.alaska.edu" in z.domain:
                logging.info(f"Copying cookie {z.name} from {z.domain} => {APIHOST}")
                cookiejar.set_cookie(requests.cookies.create_cookie(domain=APIHOST, name=z.name, value=z.value))

        log.info(f"Generated cookies: {cookiejar}")
        final_request = session.get(url, cookies=cookiejar)

        log.info(f"Final request returned: {final_request.status_code} (Expect 200)")
        self.assertTrue(final_request.status_code == 200)


class authed_download_test(unittest.TestCase):
    # Check that we get a URS auth redirect for auth'd downloads
    def test_urs_auth_redirect_for_auth_downloads(self):
        url = f"{APIROOT}/{METADATA_FILE}"
        global cookiejar

        log.info(f"Hitting {url} with cookies to check for redirect")
        r = requests.get(url, cookies=cookiejar, allow_redirects=False)

        log.info(f"Result r.status_code: {r.status_code} (Expect 303)")
        self.assertTrue(r.status_code == 303)

        log.info(f"Result r.is_redirect: {r.is_redirect} (Expect True)")
        self.assertTrue(r.is_redirect)

        log.info(f"Result r.headers['Location']: {r.headers['Location']}")
        self.assertTrue(r.headers['Location'] is not None)

        log.info(f"Make sure 'Location' header is not redirecting to URS")
        self.assertTrue('oauth/authorize' not in r.headers['Location'])

    # Check that range requests work
    def test_range_request_works(self):
        url = f"{APIROOT}/{METADATA_FILE}"
        headers = {"Range": "bytes=1035-1042"}
        global cookiejar

        log.info(f"Making range request ({headers}) from {url}")
        r = requests.get(url, cookies=cookiejar, headers=headers)

        log.info(f'Range Request Return Code: {r.status_code} (Expect 206)')
        self.assertTrue(r.status_code == 206)

        log.info(f"Range Request returned {len(r.text)} bytes of data.  (Expect 8) ")
        log.info(f"Range Data: {r.text}")
        self.assertTrue(len(r.text) == 8)

    # Check that approved users can access PRIVATE data:
    def test_approved_user_can_access_private_data(self):
        url = f'{APIROOT}/PRIVATE/ACCESS/testfile'
        global cookiejar

        log.info(f"Attempting to access an approved PRIVATE file: {url}")
        r = requests.get(url, cookies=cookiejar)

        log.info(f"APPROVED Private File check: {r.status_code} (Expect 200)")
        self.assertTrue(r.status_code == 200)

    # Check that approved users CAN'T access PRIVATE data they don't have access to:
    def test_approved_user_cant_access_private_data(self):
        url = f"{APIROOT}/PRIVATE/NOACCESS/testfile"
        global cookiejar

        log.info(f"Attempting to access an UNapproved PRRIVATE file: {url}")
        r = requests.get(url, cookies=cookiejar)

        log.info(f"UNAPPROVED Private File check: {r.status_code} (Expect 403)")
        self.assertTrue(r.status_code == 403)

    # Validating objects with prefix, works
    def test_validating_objects_with_prefix(self):
        url = f"{APIROOT}/SA/BROWSE/dir1/dir2/deepfile.txt"
        global cookiejar

        log.info(f"Attempting to validate an object with a prefix works: {url}")
        r = requests.get(url, cookies=cookiejar)

        log.info(f'Checking file content: {r.content} (Should say "successfully downloaded")')
        self.assertTrue("file was successfully downloaded" in str(r.content))

        log.info(f"Pre-fixed object Return Code: {r.status_code} (Expect 200)")
        self.assertTrue(r.status_code == 200)

    # Validating custom headers
    def test_validate_custom_headers(self):
        url = f"{APIROOT}/{METADATA_FILE_CH}"
        header_name = 'x-rainheader1'
        global cookiejar

        log.info(f"Checking custom header ({header_name}) value for {url}")
        r = requests.get(url, cookies=cookiejar, allow_redirects=False)
        log.info(f"Got headers {r.headers}")

        header_value = r.headers.get(header_name)
        log.info(f"{header_name} had value '{header_value}' (Expect 'rainheader1 value')")
        self.assertTrue(r.headers.get(header_name) is not None)

    # Validate /locate handles complex configuration keys
    def test_validate_locate_handles_complex_configuration_key(self):
        url = f"{APIROOT}/locate?bucket_name={LOCATE_BUCKET}"
        global cookiejar

        log.info(f"Attempting to get bucket map paths for {LOCATE_BUCKET} @ {url}")
        r = requests.get(url, cookies=cookiejar)

        log.info(f'Paths Output Should equal {MAP_PATHS}: {r.content}')

        paths = sorted(json.loads(r.content))
        self.assertEqual(paths, MAP_PATHS)

    # Validate EDL token works (if a little incestously)
    def test_vallidate_bearer_token_works(self):
        url = f"{APIROOT}/{METADATA_FILE}"
        global cookiejar

        # Find the token
        token = None
        for cookie in cookiejar:
            # Find the 'asf-urs' cookie...
            if cookie.name == 'asf-urs':
                # Grab the JWT payload:
                cookie_b64 = cookie.value.split(".")[1]
                # Fix the padding:
                cookie_b64 += '=' * (4 - (len(cookie_b64) % 4))
                # Decode & Load...
                cookie_json = json.loads(base64.b64decode(cookie_b64))
                if 'urs-access-token' in cookie_json:
                    token = cookie_json['urs-access-token']

        log.info(f"Make sure we were able to decode a token from the cookie: {token} (Expect not None)")
        self.assertTrue(token is not None)

        log.info(f"Attempting to download {url} using the token as a Bearer token")
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"})

        log.info(f"Bearer Token Download attempt Return Code: {r.status_code} (Expect 200)")
        # FIXME: This should work, but not until its release into production
        # self.assertEqual(r.status_code, 200)


class jwt_blacklist_test(unittest.TestCase):

    def test_validate_jwt_blacklist(self):
        url = f"{APIROOT}/{METADATA_FILE}"
        # global cookiejar

        os.environ["BLACKLIST_ENDPOINT"] = "https://s3-us-west-2.amazonaws.com/asf.rain.code.usw2/jwt_blacklist.json"
        log.info(f"Using the endpoint: {os.getenv('BLACKLIST_ENDPOINT')} to test JWT blacklist functionality")
        # log.debug(f"The cookiejar {cookiejar}")
        aws_lambda = "teadev2-jenk-same-EgressLambda"  # TODO: update to be  dynamic
        test_env_vars = '{"BLACKLIST_ENDPOINT": "https://s3-us-west-2.amazonaws.com/asf.rain.code.usw2/jwt_blacklist.json"}'
        os.system(f'aws lambda update-function-configuration --function-name {aws_lambda} --environment {test_env_vars}')

        headers = {{
            "first_name": "Brian",
            "last_name": "Badguy",
            "urs-user-id": "badguy1231",
            "urs-access-token": "longtokenvalue",
            "urs-groups": [],
            "iat": 1619103148,
            "exp": 1619707948
        }}

        r = requests.get(url, headers=headers)
        print(f"JWT BLACKLIST test code: {r.status_code}")


def main():
    failures = 0
    tests = 0

    # We need the tests to run in this order.
    for test in (unauthed_download_test, auth_download_test, authed_download_test, jwt_blacklist_test):
        suite = unittest.TestLoader().loadTestsFromTestCase(test)
        result = unittest.TextTestRunner().run(suite)

        # Check the results
        if result.failures:
            # Unexpected asserts
            log.info(f"Test {test().id()} had {len(result.failures)} Failures")
            failures += len(result.failures)

        if result.errors:
            # Malformed Tests
            log.info(f"Test {test().id()} had {len(result.errors)} Errors")
            failures += len(result.errors)

        tests += result.testsRun

    log.info(f"Test had {failures} failures in {tests} tests")
    # Build Test File Json Object
    if (failures < 1):
        message = "All Tests Passed"
        color = "success"
        exit_code = 0
    elif (failures < 3):
        message = f"{failures} of {tests} Tests Failed ⚠z"
        color = "important"
        exit_code = 1
    else:
        message = f"{failures} of {tests} Tests Failed ☠"
        color = "critical"
        exit_code = 1

    # Write out the string
    testresults = json.dumps({"schemaVersion": 1, "label": "Tests", "message": message, "color": color})

    # Required to make the file public and usable as input for the badge.
    acls_and_stuff = {"CacheControl": "no-cache", "Expires": datetime(2015, 1, 1),
                      "ContentType": "application/json", "ACL": "public-read"}

    # Dump results to S3.
    log.info(f"Writing test results: {testresults}")
    boto3.resource('s3').Object(TEST_RESULT_BUCKET, TEST_RESULT_OBJECT).put(Body=testresults, **acls_and_stuff)

    # We need a non-zero exit code if we had any failures
    sys.exit(exit_code)


if __name__ == '__main__':
    if env_var_check():
        main()
