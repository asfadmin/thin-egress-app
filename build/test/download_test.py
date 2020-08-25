import argparse
import sys
import unittest
import os
import boto3
import requests
from requests.auth import HTTPBasicAuth
import logging
import json

logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)


# Set environment variables
STACKNAME = os.getenv("STACKNAME_SAME")
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION")
aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

# Connect to AWS
client = boto3.client('apigateway', region_name=AWS_DEFAULT_REGION, aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key)


# Get EgressGateway Rest API ID from AWS
dict = client.get_rest_apis()
for item in dict['items']:
    if item['name'] == f"{STACKNAME}-EgressGateway":
        id = item['id']

API = id
cookiejar = []

METADATA_FILE = 'SA/METADATA_GRD_HS/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml'
METADATA_FILE_CH = 'SA/METADATA_GRD_HS_CH/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml'
METADATA_CHECK = '<gco:CharacterString>S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml</gco:CharacterString>'
BROWSE_FILE = 'SA/BROWSE/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.jpg'

# Get the API ROOT
APIROOT = f"https://{API}.execute-api.{AWS_DEFAULT_REGION}.amazonaws.com/API"


class download_test(unittest.TestCase):

    # Validate that auth process is successful
    def test_auth_process_is_successful(self):
        url = f"{APIROOT}/{METADATA_FILE}"

        urs_username = os.getenv("URS_USERNAME")
        urs_password = os.getenv("URS_PASSWORD")

        session = requests.session()
        request = session.get(url, auth=HTTPBasicAuth(urs_username, urs_password))
        url_earthdata = request.url
        login2 = session.get(url_earthdata, auth=HTTPBasicAuth(urs_username, urs_password))
        cookiejar = session.cookies
        final_request = session.get(url, cookies=cookiejar)
        self.assertTrue(final_request.status_code == 200)

    # Check that we get a URS auth redirect for auth'd downloads
    def test_urs_auth_redirect_for_auth_downloads(self):
        r = requests.get(f"{APIROOT}/{METADATA_FILE}", cookies=cookiejar, allow_redirects=False)
        self.assertFalse(r.url is None)
        logging.info(f'redirect status : {r.status_code}')
        self.assertTrue(r.is_redirect)
        self.assertTrue(r.headers['Location'] is not None)

    # Check that public files are returned without auth
    def test_check_that_images_are_public(self):
        r = requests.get(f'{APIROOT}/{BROWSE_FILE}', cookies=cookiejar)
        logging.info(f'Public Image Test Content_Type : {r.status_code}')
        self.assertTrue('Content-Type' in r.headers and r.headers['Content-Type'] == 'image/jpeg')



    # Check for 404 on bad request
    def test_404_on_bad_request(self):
        r = requests.get(f"{APIROOT}/bad/url.ext", cookies=cookiejar)
        self.assertTrue(r.status_code == 404)

    # Check that range requests work
    def test_range_request_works(self):
        url = f"{APIROOT}/{METADATA_FILE}"
        headers = {"Range": "bytes=1035-1042"}
        r = requests.get(url, cookies=cookiejar, headers=headers)
        assert len(r.text) <= 1042  # not exactly 1042, because r.text does not include header

    # Check that a bad cookie value causes URS redirect:
    def test_bad_cookie_value_cause_URS_redirect(self):
        url = f"{APIROOT}/{METADATA_FILE}"

        cookies = {'urs_user_id': 'badusername',
                   'urs_access_token': 'BLABLABLA'}

        r = requests.post(url, cookies)
        self.assertTrue(r.is_redirect)

    # Check that approved users can access PRIVATE data:
    def test_approved_user_can_access_private_data(self):
        url = f'{APIROOT}/PRIVATE/ACCESS/testfile'
        r = requests.get(url, cookies=cookiejar)
        self.assertTrue(r.status_code == 200)

    # Check that approved users CAN'T access PRIVATE data they don't have access to:
    def test_approved_user_cant_access_private_data(self):
        url = f"{APIROOT}/PRIVATE/NOACCESS/testfile"
        r = requests.get(url, cookies=cookiejar)
        self.assertTrue(r.status_code == 403)

    # Validating objects with prefix, works
    def test_validating_objects_with_prefix(self):
        url = f"{APIROOT}/SA/BROWSE/dir1/dir2/deepfile.txt"
        r = requests.get(url, cookies=cookiejar)
        logging.info(f'Should say , The file was successfully downloaded : {r.content}')
        self.assertTrue(r.status_code == 200)

    # Validating custom headers
    def test_validate_custom_headers(self):
        url = f"{APIROOT}/{METADATA_FILE_CH}"
        r = requests.get(url, cookies=cookiejar, allow_redirects=False)
        self.assertTrue(r.headers.get('x-rainheader-1') is not None)

    # Validate /locate handles complex configuration keys
    # LOCATE_OUTPUT should be set e.g. '["SA/OCN", "SA/OCN_CH", "SB/OCN_CN", "SB/OCN_CH"]'
    # LOCATE_BUCKET should be set
    def test_validate_locate_handles_complex_configuration_key(self):
        locate_bucket = os.getenv("LOCATE_BUCKET")
        url = f"{APIROOT}/locate?bucket_name={locate_bucket}"
        r = requests.get(url, cookies=cookiejar)
        logging.info(f'Output Should equal "SA/OCN", "SA/OCN_CH", "SB/OCN_CN", "SB/OCN_CH"  : {r.content}')
        self.assertEqual(r.content, b'["SA/OCN", "SA/OCN_CH", "SB/OCN_CN", "SB/OCN_CH"]')


def main():
    thetest = download_test()
    result = thetest.run()
    failures = len(result.failures)
    # Build Test File Json Object
    if(failures < 1):
        success_msg = '{"schemaVersion": 1, "label": "Tests", "message": "All Tests Passed", "color": "success"}'
        testresults = success_msg
    else:
        failure_msg = f'{"schemaVersion": 1, "label": "Tests", "message": "{failures} Tests Failed", "color": "failure"}'
        testresults= failure_msg
    with open('testresults.text') as json_file:
        s3 = boto3.resource('s3')
        s3.meta.client.upload_file(json_file.name, 'asf.public.code', 'thin-egress-app/testresults.json')
    # for fail in result.failures:
    #     print(f'stacktrace: {fail[1]}')
    #     print(fail[0].longMessage)
    #     print(fail[0])
    #
    # for error in result.errors:
    #     print(f'stacktrace: {error[1]}')
    #     print(error[0])


if __name__ == '__main__':
    main()
