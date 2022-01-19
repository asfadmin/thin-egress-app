import importlib
import logging
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
