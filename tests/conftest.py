import importlib
import logging
import os
import pathlib
import sys
from typing import IO, Any
from unittest import mock

import pytest

# Can't import normally because 'lambda' is a reserved word
# Need to import the app module first because it will override the log level at import time
_ = importlib.import_module("lambda.app")

RESOURCES_PATH = pathlib.Path(__file__).parent.joinpath("resources/").absolute()

logging.getLogger().setLevel(0)


# Mock out calls to boto3 by replacing the module in sys.modules
real_boto3 = importlib.import_module("boto3")
mock_boto3 = mock.create_autospec(real_boto3)
sys.modules["boto3"] = mock_boto3


@pytest.fixture(scope="session", autouse=True)
def aws_config():
    """Set up aws cli/boto configuration

    This makes sure we don't accidentally touch real resources.
    """
    # NOTE: This will persist beyond the pytest session,
    # however, the process should terminate immediately afterwards.
    os.environ["AWS_ACCESS_KEY_ID"] = "TEST_ACCESS_KEY_ID"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "TEST_SECRET_ACCESS_KEY"
    os.environ["AWS_SECURITY_TOKEN"] = "TEST_SECURITY_TOKEN"
    os.environ["AWS_SESSION_TOKEN"] = "TEST_SESSION_TOKEN"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


class Resources():
    """Helper for getting test resources"""
    def open(self, file, *args, **kwargs) -> IO[Any]:
        return (RESOURCES_PATH / file).open(*args, **kwargs)


@pytest.fixture(scope="session")
def resources():
    return Resources()


@pytest.fixture
def boto3():
    mock_boto3.reset_mock()
    return mock_boto3
