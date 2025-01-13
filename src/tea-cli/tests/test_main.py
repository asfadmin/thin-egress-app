import pytest
from tea_cli.main import get_parser, main


@pytest.fixture
def parser():
    return get_parser()


def test_parser_no_args(parser):
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_main_no_args():
    with pytest.raises(SystemExit):
        main([])
