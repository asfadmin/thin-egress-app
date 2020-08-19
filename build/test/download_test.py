import unittest
import os
import boto3
import requests

STACKNAME = os.getenv("STACKNAME_SAME")
AWS_DEFAULT_REGION = "us-east-1"
# os.getenv("AWS_DEFAULT_REGION")

# aws apigateway get - rest - apis - -query "items[?name=='${STACKNAME}-EgressGateway'].id" - -output = text - -region ${AWS_DEFAULT_REGION}

aws_access_key_id = os.getenv("aws_access_key_id")
aws_secret_access_key = os.getenv("aws_secret_access_key")
aws_session_token = os.getenv("aws_session_token")

client = boto3.client('apigateway', region_name=AWS_DEFAULT_REGION, aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)

dict = client.get_rest_apis()
for item in dict['items']:
    # if item['name'] == f'{STACKNAME}-EgressGateway':
    if item['name'] == STACKNAME:
        id = item['id']


API=id

METADATA_FILE = 'SA/METADATA_GRD_HS/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml'
METADATA_FILE_CH = 'SA/METADATA_GRD_HS_CH/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml'
METADATA_CHECK = '<gco:CharacterString>S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml</gco:CharacterString>'
BROWSE_FILE = 'SA/BROWSE /S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.jpg'

# Get the API ROOT
APIROOT =f'https://${API}.execute-api.${AWS_DEFAULT_REGION}.amazonaws.com/API'


class download_test():

    # Check that we get a URS auth redirect for auth'd downloads
    def test_urs_auth_redirect_for_auth_downloads(self):
        r = requests.get(f'{APIROOT}{METADATA_FILE}')
        self.assertFalse(r.url is None)

    def test_check_that_images_are_public(self):
        r = requests.get(f'{APIROOT}{BROWSE_FILE}')
        self.assertTrue("Content-Type" in r.headers and r.headers['Content-Type'] == 'image/jpeg')

    # Validate that auth process is successful
    def test_auth_process_is_successful(self):

        url = f'{APIROOT}/{METADATA_FILE}'
        values = {
            'urs_username': 'myc00lusername',
            'urs_password': 'Myl33tPassw0rd12'
        }
        session = requests.session()
        r = session.post(url, data=values)
        self.assertFalse(r.cookies is None)

    # Check for 404 on bad request
    def test_404_on_bad_request(self):
        r = requests.get(f'{APIROOT}/bad/url.ext')
        self.assertTrue(r.status_code == 404)

    def test_range_request_works(self):
        url = "http://tools.ietf.org/rfc/rfc2822.txt"
        headers = {"Range": "bytes=1035-1042"}
        r = requests.get(url, headers=headers)
        assert len(r.text) <= 1042  # not exactly 101, because r.text does not include header

    # Check that a bad cookie value causes URS redirect:
    def test_bad_cookie_value_cause_URS_redirect(self):
        url = f'{APIROOT}/{METADATA_FILE}'

        cookies = {'cookie_test': 'imabadcookie','urs_user_id':'badusername',
        'urs_access_token':'BLABLABLA'}

        r = requests.post(url, cookies)
        self.assertFalse(r.url is None)

    # Check that approved users can access PRIVATE data:
    def test_approved_user_can_access_private_data(self):
        url = f'{APIROOT}/PRIVATE/ACCESS/testfile '
        r = requests.get(url)
        self.assertTrue(r.status_code == 200)

    # Check that approved users CAN'T access PRIVATE data they don't have access to:
    def test_approved_user_cant_access_private_data(self):
        url = f'{APIROOT}/PRIVATE/NOACCESS/testfile '
        r = requests.get(url)
        self.assertTrue(r.status_code == 403)

    # Validating objects with prefix
    def test_validating_objects_with_prefix(self):
        url = f'{APIROOT}/SA/BROWSE/dir1/dir2/deepfile.txt'
        r = requests.get(url)
        self.assertTrue(r.status_code == 200)

    # Validating custom headers
    def test_validate_custom_headers(self):
        url = f'{APIROOT}/{METADATA_FILE_CH}'
        r = requests.get(url)
        self.assertTrue(r.headers.get('x-rainheader') is not None)

    # Validate /locate handles complex configuration keys
    # LOCATE_OUTPUT should be set e.g. '["SA/OCN", "SA/OCN_CH", "SB/OCN_CN", "SB/OCN_CH"]'
    # LOCATE_BUCKET should be set
    def test_validate_locate_handles_complex_configuration_key(self):
        locate_bucket = 'locate bucket'
        url = f'{APIROOT}/locate?bucket_name={locate_bucket}'
        r = requests.get(url)
        self.assertEquals(r.content,'["SA/OCN", "SA/OCN_CH", "SB/OCN_CN", "SB/OCN_CH"]')

    # Upload test results
    s3 = boto3.resource('s3')
    s3.meta.client.upload_file('/tmp/testresults.json', '//asf.public.code/thin-egress-app/', 'testresults.json')


if __name__ == '__main__':
    unittest.main()
