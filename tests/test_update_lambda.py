import importlib
import io
import json
from unittest import mock

import pytest

MODULE = "lambda.update_lambda"
update_lambda = importlib.import_module(MODULE)


@pytest.fixture
def context():
    return mock.Mock(aws_request_id="request_1234")


@mock.patch(f"{MODULE}.get_region_cidrs")
@mock.patch(f"{MODULE}.cfnresponse")
def test_lambda_handler(mock_cfnresponse, mock_get_region_cidrs, boto3, context, monkeypatch):
    monkeypatch.setenv("iam_role_name", "role_1234")
    client = boto3.client("iam")
    client.list_role_policies.return_value = {
        "PolicyNames": ["foo", "bar"]
    }
    mock_get_region_cidrs.return_value = ["10.0.0.0/8"]
    event = {"ResponseURL": "https://example.com"}

    update_lambda.lambda_handler(event, context)

    client.put_role_policy.assert_called_once()
    client.delete_role_policy.assert_any_call(RoleName="role_1234", PolicyName="foo")
    client.delete_role_policy.assert_any_call(RoleName="role_1234", PolicyName="bar")
    mock_cfnresponse.send.assert_called_once_with(event, context, mock_cfnresponse.SUCCESS, {"Data": mock.ANY})


@mock.patch(f"{MODULE}.get_region_cidrs")
@mock.patch(f"{MODULE}.cfnresponse")
def test_lambda_handler_no_response(mock_cfnresponse, mock_get_region_cidrs, boto3, context, monkeypatch):
    monkeypatch.setenv("iam_role_name", "role_1234")
    client = boto3.client("iam")
    client.list_role_policies.return_value = {
        "PolicyNames": ["foo", "bar"]
    }
    mock_get_region_cidrs.return_value = ["10.0.0.0/8"]
    event = {}

    update_lambda.lambda_handler(event, context)

    client.put_role_policy.assert_called_once()
    client.delete_role_policy.assert_any_call(RoleName="role_1234", PolicyName="foo")
    client.delete_role_policy.assert_any_call(RoleName="role_1234", PolicyName="bar")
    mock_cfnresponse.send.assert_not_called()


@mock.patch(f"{MODULE}.get_region_cidrs")
@mock.patch(f"{MODULE}.cfnresponse")
def test_lambda_handler_no_policy_names(mock_cfnresponse, mock_get_region_cidrs, boto3, context):
    client = boto3.client("iam")
    client.list_role_policies.return_value = {}
    mock_get_region_cidrs.return_value = ["10.0.0.0/8"]
    event = {}

    update_lambda.lambda_handler(event, context)

    client.put_role_policy.assert_called_once()
    client.delete_role_policy.assert_not_called()
    mock_cfnresponse.send.assert_not_called()


@mock.patch(f"{MODULE}.get_region_cidrs")
@mock.patch(f"{MODULE}.cfnresponse")
def test_lambda_handler_error(mock_cfnresponse, mock_get_region_cidrs, context):
    mock_get_region_cidrs.side_effect = Exception("mock exception")
    event = {"ResponseURL": "https://example.com"}

    update_lambda.lambda_handler(event, context)

    mock_cfnresponse.send.assert_called_once_with(event, context, mock_cfnresponse.FAILED, {"Data": mock.ANY})


@mock.patch(f"{MODULE}.get_region_cidrs")
@mock.patch(f"{MODULE}.cfnresponse")
def test_lambda_handler_error_no_response(mock_cfnresponse, mock_get_region_cidrs, context):
    mock_get_region_cidrs.side_effect = Exception("mock exception")
    event = {}

    update_lambda.lambda_handler(event, context)

    mock_cfnresponse.send.assert_not_called()


@mock.patch(f"{MODULE}.urllib.request")
def test_get_region_cidrs(mock_request):
    data = json.dumps({
        "prefixes": [
            # Correct service and region
            {
                "ip_prefix": "10.10.0.0/24",
                "service": "AMAZON",
                "region": "us-east-1"
            },
            # Wrong service
            {
                "ip_prefix": "10.20.0.0/24",
                "service": "SOMETHING_ELSE",
                "region": "us-east-1"
            },
            # Wrong region
            {
                "ip_prefix": "10.30.0.0/24",
                "service": "AMAZON",
                "region": "us-west-2"
            },
            # Two prefixes that should be merged
            {
                "ip_prefix": "10.40.0.0/24",
                "service": "AMAZON",
                "region": "us-east-1"
            },
            {
                "ip_prefix": "10.40.0.0/16",
                "service": "AMAZON",
                "region": "us-east-1"
            },
        ]
    }).encode()
    mock_request.urlopen.return_value = io.BytesIO(data)
    ips = update_lambda.get_region_cidrs("us-east-1")

    assert ips == [
        "10.10.0.0/24",
        "10.40.0.0/16",
        "10.0.0.0/8"
    ]


def test_get_base_policy(monkeypatch):
    monkeypatch.setenv("vpcid", "vpc_1234")

    policy = update_lambda.get_base_policy("prefix_1234")
    assert isinstance(policy, dict)
    for statement in policy["Statement"]:
        for resource in statement["Resource"]:
            assert resource.startswith("arn:aws:s3:::prefix_1234")
