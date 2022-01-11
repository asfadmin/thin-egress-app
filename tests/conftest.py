import importlib
import logging
import sys
from unittest import mock

import pytest

from tests import open_resource

# Can't import normally because 'lambda' is a reserved word
# Need to import the app module first because it will override the log level at import time
_ = importlib.import_module("lambda.app")

logging.getLogger().setLevel(0)


# Mock out calls to boto3 by replacing the module in sys.modules
real_boto3 = importlib.import_module("boto3")
mock_boto3 = mock.create_autospec(real_boto3)
sys.modules["boto3"] = mock_boto3


# TODO(reweeden): Use an existing pytest plugin
class Resources():
    """Helper for getting test resources"""
    def open(self, *args, **kwargs):
        return open_resource(*args, **kwargs)


@pytest.fixture(scope="session")
def resources():
    return Resources()


@pytest.fixture
def boto3():
    mock_boto3.reset_mock()
    return mock_boto3
