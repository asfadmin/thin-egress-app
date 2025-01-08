import logging
import os
import textwrap
from pathlib import Path

import boto3
import pytest
from moto import mock_aws


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
def private_key():
    """Used for signing fake JWTs in unit tests"""
    return textwrap.dedent(
        """
        -----BEGIN PRIVATE KEY-----
        MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAzXKhtCOkUvA5POUW
        ddN8G0wHTQfQg6wp7NXmID8AW0FMU5ZOhAl0l1dGWs9U83C4IA8Hqbpe/XbY8CuT
        SOEWUwIDAQABAkAU5/5Wg238Vp+sd69ybAPsDy+LAimQzJszk4yoaWDS6EI1DcBV
        npb7lFvGCcnUe57Lm6DhWD1EnDYhD451VrYRAiEA/8z3pXYDBSJoWA79xrsq2cze
        4oYwhTWtzueU8+Mlf0kCIQDNm55qR00BUbhBO/tTP2VCC2OQd/v9I+UIcwIL9Wg8
        uwIhAOpwUAe1QM9T2Y3bL3sTzxIOUbgKhC2SJNmcJUfgxl0BAiEAq+nbageV9m1q
        v3i0qqWON8uoAyqfkshJf2gSJQebkXMCIFUVSih1R6FqkoP2HFOZvJiRQnfO6shL
        jrhQOs2SXP05
        -----END PRIVATE KEY-----
        """,
    )


@pytest.fixture(scope="session")
def data_path():
    return Path(__file__).parent.joinpath("data").resolve()


@pytest.fixture
def client_iam():
    with mock_aws():
        yield boto3.client("iam")


@pytest.fixture
def client_lambda():
    with mock_aws():
        yield boto3.client("lambda")
