import logging
import os
from pathlib import Path

import boto3
import pytest
from moto import mock_iam, mock_lambda


@pytest.fixture(autouse=True)
def root_logger():
    """Set up logger for pytest"""
    root = logging.getLogger()
    for handler in root.handlers:
        root.removeHandler(handler)
    root.setLevel(logging.DEBUG)


@pytest.fixture(scope="session", autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="session")
def data_path():
    return Path(__file__).parent.joinpath("data").resolve()


@pytest.fixture
def client_iam():
    with mock_iam():
        yield boto3.client("iam")


@pytest.fixture
def client_lambda():
    with mock_lambda():
        yield boto3.client("lambda")
