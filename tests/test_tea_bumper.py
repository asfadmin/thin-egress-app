import io
import zipfile
from base64 import b64encode
from unittest import mock

import pytest

from thin_egress_app import tea_bumper

MODULE = "thin_egress_app.tea_bumper"


@pytest.fixture
def context():
    return mock.Mock(aws_request_id="request_1234")


@pytest.fixture
def test_lambda_code_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "lambda_handler.py",
            "lambda_handler = lambda event, context: None"
        )
    return buf.getvalue()


@pytest.fixture
def test_lambda(client_iam, client_lambda, test_lambda_code_zip):
    role = client_iam.create_role(
        RoleName="lambda-role",
        AssumeRolePolicyDocument="{}"
    )["Role"]

    client_lambda.create_function(
        FunctionName="test-lambda",
        Runtime="python3.10",
        Role=role["Arn"],
        Code={
            "ZipFile": b64encode(test_lambda_code_zip)
        }
    )
    print(client_lambda.list_functions())


# @mock_lambda
@mock.patch(f"{MODULE}.datetime")
@mock.patch(f"{MODULE}.TEA_LAMBDA_NAME", "test-lambda")
def test_lambda_handler(mock_datetime, client_lambda, test_lambda, context):
    del test_lambda

    mock_datetime.utcnow.return_value = 0

    tea_bumper.lambda_handler(None, context)

    assert client_lambda.get_function_configuration(
        FunctionName="test-lambda"
    )["Environment"] == {
        "Variables": {
            "BUMP": "0, request_1234"
        }
    }
