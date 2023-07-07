import argparse
import logging
import sys


def main(args=None):
    parser = get_parser()
    parsed_args = parser.parse_args(args=args)

    setup_logger(parsed_args)
    parsed_args.func(parsed_args)


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Thin Egress App Command Line Tool")
    parser.add_argument("-v", help="enable verbose output", action="store_true", dest="verbose")
    subparsers = parser.add_subparsers(required=True, dest="command")

    return parser


def setup_logger(args: argparse.Namespace):
    root_logger = logging.getLogger("tea_cli")
    stdout_handler = logging.StreamHandler(sys.stdout)
    root_logger.addHandler(stdout_handler)

    if args.verbose:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.INFO)
