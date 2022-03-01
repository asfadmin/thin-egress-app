import contextlib
import copy
import time

import boto3
import pytest
import requests


@pytest.fixture(scope="session")
def aws_function_name(stack_name):
    return f"{stack_name}-EgressLambda"


@pytest.fixture
def aws_lambda_client():
    return boto3.client("lambda")


@pytest.fixture
def endpoint_patcher(aws_lambda_client, aws_function_name):
    return EndpointPatcher(aws_lambda_client, aws_function_name)


# TODO(reweeden): Instead of patching the blacklist which requires that we have proper AWS credentials,
# lets just use two different accounts instead
class EndpointPatcher():
    def __init__(self, aws_lambda_client, aws_function_name):
        self.aws_lambda_client = aws_lambda_client
        self.aws_function_name = aws_function_name

    @contextlib.contextmanager
    def __call__(self, endpoint):
        endpoint_dict = {"BLACKLIST_ENDPOINT": endpoint}
        lambda_configuration = self.aws_lambda_client.get_function_configuration(
            FunctionName=self.aws_function_name
        )

        new_env_vars = lambda_configuration["Environment"]
        old_env_vars = copy.deepcopy(new_env_vars)
        new_env_vars["Variables"].update(endpoint_dict)

        self.aws_lambda_client.update_function_configuration(
            FunctionName=self.aws_function_name,
            Environment=new_env_vars
        )

        time.sleep(3)

        try:
            yield
        finally:
            self.aws_lambda_client.update_function_configuration(
                FunctionName=self.aws_function_name,
                Environment=old_env_vars
            )
            time.sleep(3)


def test_validate_invalid_jwt(urls, auth_cookies, endpoint_patcher):
    url = urls.join(urls.METADATA_FILE)
    # TODO(reweeden): config?
    endpoint = "https://s3-us-west-2.amazonaws.com/asf.rain.code.usw2/jwt_blacklist.json"

    with endpoint_patcher(endpoint):
        r = requests.get(url, cookies=auth_cookies, allow_redirects=False)

        assert r.is_redirect is True
        assert r.headers['Location'] is not None
        assert 'oauth/authorize' in r.headers['Location']


def test_validate_valid_jwt(urls, auth_cookies, endpoint_patcher):
    url = urls.join(urls.METADATA_FILE)
    # TODO(reweeden): Config?
    endpoint = "https://s3-us-west-2.amazonaws.com/asf.rain.code.usw2/valid_jwt_blacklist_test.json"

    with endpoint_patcher(endpoint):
        r = requests.get(url, cookies=auth_cookies)

        assert r.status_code == 200
