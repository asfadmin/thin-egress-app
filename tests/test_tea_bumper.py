import importlib
from unittest import mock

import pytest

MODULE = "lambda.tea_bumper"
tea_bumper = importlib.import_module(MODULE)


@pytest.fixture
def context():
    return mock.Mock(aws_request_id="request_1234")


@mock.patch(f"{MODULE}.datetime")
def test_lambda_handler(mock_datetime, boto3, context):
    mock_datetime.utcnow.return_value = 0

    client = boto3.client("lambda")
    client.get_function_configuration.return_value = {
        "Environment": {
            "Variables": {
                "foo": "bar"
            }
        }
    }

    tea_bumper.lambda_handler(None, context)

    client.update_function_configuration.assert_called_once_with(
        FunctionName=None,
        Environment={
            "Variables": {
                "foo": "bar",
                "BUMP": "0, request_1234"
            }
        }
    )
