import json
import logging
import netrc
import os
import urllib.parse
from datetime import datetime

import boto3
import pytest
import requests

logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger("botocore").setLevel(logging.INFO)


def get_env(key):
    """Helper to prevent environment from being printed"""
    __tracebackhide__ = True
    val = os.environ.get(key)

    if val is None:
        raise KeyError(key)

    return val


def pytest_addoption(parser):
    parser.addoption(
        "--stack-name",
        help="Name of the cloudformation stack",
        required=True,
        action="store",
    )
    parser.addoption(
        "--url",
        help=(
            "The base URL of the API to test. "
            "If it is omitted then boto3 will be used to get the execute api URL"
        ),
        action="store",
    )
    parser.addoption(
        "--profile",
        help="AWS profile name to use",
        action="store",
    )
    parser.addoption(
        "--netrc",
        help="Netrc file to get auth credentials from",
        action="store",
    )

    def S3Object(text):
        if "/" not in text:
            raise ValueError("format should be 'bucket/object'")

        return text.split("/", 1)

    parser.addoption(
        "--test-results",
        help="S3 bucket/object to upload test results to.",
        action="store",
        type=S3Object,
    )


def pytest_report_header(config):
    profile = config.getoption("--profile") or "default"
    stack_name = config.getoption("--stack-name")

    return f"AWS: Profile={profile}, CloudFormation Stack={stack_name}"


@pytest.fixture(scope="session", autouse=True)
def _configure_from_options(aws_profile):
    kwargs = {}

    if aws_profile:
        kwargs["profile_name"] = aws_profile

    boto3.setup_default_session(**kwargs)


@pytest.fixture(scope="session")
def _netrc(request):
    filename = request.config.getoption("--netrc")
    if filename is None:
        return

    return netrc.netrc(filename)


@pytest.fixture(scope="session")
def creds(_netrc):
    return CredsHelper(_netrc)


class Secret():
    def __init__(self, val):
        self.val = val

    def __repr__(self):
        return "'******'"

    def __str__(self):
        return self.val


class CredsHelper():
    def __init__(self, netrc_file):
        self.netrc_file = netrc_file

    def get(self, url):
        if self.netrc_file:
            res = urllib.parse.urlparse(url)
            entry = self.netrc_file.hosts.get(res.hostname)
            if entry:
                login, _, password = entry
                return login, Secret(password)

        return get_env("URS_USERNAME"), Secret(get_env("URS_PASSWORD"))


@pytest.fixture(scope="session")
def stack_name(request):
    return request.config.getoption("--stack-name")


@pytest.fixture(scope="session")
def _api_url(request):
    # Don't request this fixture directly. Use `api_url` instead.
    return request.config.getoption("--url")


@pytest.fixture(scope="session")
def aws_profile(request):
    return request.config.getoption("--profile")


@pytest.fixture(scope="session")
def api_url(_api_url, request):
    if _api_url:
        return _api_url

    api_host = request.getfixturevalue("_boto3_api_host")
    return f"https://{api_host}/API/"


@pytest.fixture(scope="session")
def _boto3_api_host(stack_name):
    # Don't request this fixture directly. Use `api_host` instead.
    client = boto3.client("apigateway")
    rest_apis = client.get_rest_apis()

    for api in rest_apis['items']:
        if api['name'] == f"{stack_name}-EgressGateway":
            return f"{api['id']}.execute-api.{client.meta.region_name}.amazonaws.com"

    raise Exception(f"Could not find API for the given stackname {stack_name}")


@pytest.fixture(scope="session")
def api_host(_api_url, request):
    if _api_url:
        parse_result = urllib.parse.urlparse(_api_url)
        return parse_result.hostname

    return request.getfixturevalue("_boto3_api_host")


@pytest.fixture(scope="session")
def urls(api_url):
    return UrlsConfig(api_url)


class UrlsConfig():
    _METADATA_FILE_NAME = "S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml"
    METADATA_FILE = f"SA/METADATA_GRD_HS/{_METADATA_FILE_NAME}"
    METADATA_FILE_CH = f"SA/METADATA_GRD_HS_CH/{_METADATA_FILE_NAME}"

    def __init__(self, base_url: str):
        self.base_url = base_url

    def join(self, *parts):
        return urllib.parse.urljoin(self.base_url, "/".join(parts))


@pytest.fixture(scope="module")
def auth_cookies(urls, api_host, creds):
    url = urls.join(urls.METADATA_FILE)
    session = requests.session()
    # Disable automatic detection of .netrc.
    session.trust_env = False

    request = session.get(url)
    url_earthdata = request.url

    urs_username, urs_password = creds.get(url_earthdata)
    session.get(url_earthdata, auth=requests.auth.HTTPBasicAuth(urs_username, str(urs_password)))
    cookiejar = session.cookies

    # Copy .asf.alaska.edu cookies to match API Address
    for z in cookiejar:
        if "asf.alaska.edu" in z.domain:
            cookiejar.set_cookie(requests.cookies.create_cookie(
                domain=api_host,
                name=z.name,
                value=z.value
            ))

    return cookiejar


# Functions that generate the JSON report file
def pytest_sessionstart(session):
    session.results = {}


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    del call

    outcome = yield
    rep = outcome.get_result()

    if rep.when == "call":
        item.session.results[item] = rep


def pytest_sessionfinish(session, exitstatus):
    del exitstatus

    test_results_config = session.config.getoption("--test-results")
    if not test_results_config:
        return

    s3_bucket, s3_object = test_results_config

    failed_amount = sum(result.failed for result in session.results.values())
    total_amount = len(session.results)

    if failed_amount < 1:
        message = "All Tests Passed"
        color = "success"
    elif failed_amount < 3:
        message = f"{failed_amount} of {total_amount} Tests Failed ⚠z"
        color = "important"
    else:
        message = f"{failed_amount} of {total_amount} Tests Failed ☠"
        color = "critical"

    # Write out the string
    testresults = json.dumps({
        "schemaVersion": 1,
        "label": "Tests",
        "message": message,
        "color": color
    })

    # Required to make the file public and usable as input for the badge.
    put_args = {
        "CacheControl": "no-cache",
        "Expires": datetime(2015, 1, 1),
        "ContentType": "application/json",
        "ACL": "public-read"
    }

    # Dump results to S3.
    boto3.resource('s3').Object(s3_bucket, s3_object).put(Body=testresults, **put_args)
