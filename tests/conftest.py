import importlib
import logging
import pathlib
import sys
from typing import IO, Any
from unittest import mock

import pytest

# Mock out calls to boto3 by replacing the module in sys.modules
real_boto3 = importlib.import_module("boto3")
mock_boto3 = mock.create_autospec(real_boto3)
sys.modules["boto3"] = mock_boto3

# Need to import these modules first because they will override the log level at import time
import thin_egress_app.app  # noqa: E402
import thin_egress_app.tea_bumper  # noqa: F401,E402

root_logger = logging.getLogger()
for handler in root_logger.handlers:
    root_logger.removeHandler(handler)
root_logger.setLevel(logging.DEBUG)

RESOURCES_PATH = pathlib.Path(__file__).parent.joinpath("resources/").absolute()


@pytest.fixture(autouse=True)
def aws_config(monkeypatch):
    """Set up aws cli/boto configuration

    This makes sure we don't accidentally touch real resources.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "TEST_ACCESS_KEY_ID")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "TEST_SECURITY_TOKEN")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "TEST_SESSION_TOKEN")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


class Resources:
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
