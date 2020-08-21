import sys
import unittest
import os
import boto3
import requests
import logging
from requests.auth import HTTPBasicAuth


# Validate that auth process is successful

url = f"https://tea-test-jenk-0.asf.alaska.edu/SA/METADATA_GRD_HS/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml"

urs_username = 'asf_automated_testing'
urs_password = 'kj=@tvxqDs#U9H7c'

session = requests.session()



request = session.get(url,  auth=HTTPBasicAuth(urs_username, urs_password))
url_earthdata = request.url
login2 = session.get(url_earthdata,auth=HTTPBasicAuth(urs_username, urs_password))
logging.debug(url_earthdata)
print(url_earthdata)
print(login2)
logging.debug(login2)
cookiejar = session.cookies
final_request = session.get(url, cookies=cookiejar)
print(f'second request : {final_request.content}')



r = requests.get(f'https://tea-test-jenk-0.asf.alaska.edu/SA/BROWSE/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.jpg', cookies=cookiejar)
print(r.status_code)
print(r.headers)
print('Content-Type' in r.headers and r.headers['Content-Type'] == 'image/jpeg')