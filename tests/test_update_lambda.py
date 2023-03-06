import io
import json
from unittest import mock

import pytest

from thin_egress_app import update_lambda

MODULE = "thin_egress_app.update_lambda"


@pytest.fixture
def context():
    return mock.Mock(aws_request_id="request_1234")


@pytest.fixture
def test_role_policy_document():
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:*", "Resource": "*"
        }
    })


@pytest.fixture
def test_role_blank(client_iam):
    role_name = "test_role"
    client_iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument="{}"
    )
    return role_name


@pytest.fixture
def test_role(test_role_blank, client_iam, test_role_policy_document):
    client_iam.put_role_policy(
        RoleName=test_role_blank,
        PolicyName="foo",
        PolicyDocument=test_role_policy_document
    )
    client_iam.put_role_policy(
        RoleName=test_role_blank,
        PolicyName="bar",
        PolicyDocument=test_role_policy_document
    )
    return test_role_blank


@mock.patch(f"{MODULE}.get_region_cidrs")
@mock.patch(f"{MODULE}.cfnresponse")
def test_lambda_handler(
    mock_cfnresponse,
    mock_get_region_cidrs,
    test_role,
    client_iam,
    context,
    monkeypatch
):
    monkeypatch.setenv("iam_role_name", test_role)
    monkeypatch.setenv("policy_name", "test_policy")

    mock_get_region_cidrs.return_value = ["10.0.0.0/8"]
    event = {"ResponseURL": "https://example.com"}

    update_lambda.lambda_handler(event, context)

    assert client_iam.list_role_policies(
        RoleName=test_role
    )["PolicyNames"] == ["test_policy"]

    mock_cfnresponse.send.assert_called_once_with(
        event,
        context,
        mock_cfnresponse.SUCCESS,
        {"Data": mock.ANY}
    )


@mock.patch(f"{MODULE}.get_region_cidrs")
@mock.patch(f"{MODULE}.cfnresponse")
def test_lambda_handler_no_response(
    mock_cfnresponse,
    mock_get_region_cidrs,
    test_role,
    client_iam,
    context,
    monkeypatch
):
    monkeypatch.setenv("iam_role_name", test_role)
    monkeypatch.setenv("policy_name", "test_policy")

    mock_get_region_cidrs.return_value = ["10.0.0.0/8"]
    event = {}

    update_lambda.lambda_handler(event, context)

    assert client_iam.list_role_policies(
        RoleName=test_role
    )["PolicyNames"] == ["test_policy"]

    mock_cfnresponse.send.assert_not_called()


@mock.patch(f"{MODULE}.get_region_cidrs")
@mock.patch(f"{MODULE}.cfnresponse")
def test_lambda_handler_no_policy_names(
    mock_cfnresponse,
    mock_get_region_cidrs,
    test_role_blank,
    client_iam,
    context,
    monkeypatch
):
    monkeypatch.setenv("iam_role_name", test_role_blank)
    monkeypatch.setenv("policy_name", "test_policy")

    mock_get_region_cidrs.return_value = ["10.0.0.0/8"]
    event = {}

    update_lambda.lambda_handler(event, context)

    assert client_iam.list_role_policies(
        RoleName=test_role_blank
    )["PolicyNames"] == ["test_policy"]

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
