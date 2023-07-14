import argparse
import logging
import sys

from tea_cli.commands import list_versions, quick_deploy

log = logging.getLogger(__name__)


def main(args=None):
    parser = get_parser()
    parsed_args = parser.parse_args(args=args)

    setup_logger(parsed_args)

    try:
        parsed_args.func(parsed_args)
    except KeyboardInterrupt:
        log.info("Cancelled")


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Thin Egress App Command Line Tool")
    parser.add_argument("-v", help="enable verbose output", action="store_true", dest="verbose")
    subparsers = parser.add_subparsers(required=True, dest="command")

    parser_list = subparsers.add_parser("list")
    configure_subparser(parser_list, list_versions)

    parser_quickdeploy = subparsers.add_parser("quickdeploy")
    configure_subparser(parser_quickdeploy, quick_deploy)

    return parser


def configure_subparser(parser: argparse.ArgumentParser, mod):
    mod.configure_parser(parser)
    parser.set_defaults(func=mod.handle_args)


def setup_logger(args: argparse.Namespace):
    root_logger = logging.getLogger("tea_cli")
    stdout_handler = logging.StreamHandler(sys.stdout)
    root_logger.addHandler(stdout_handler)

    if args.verbose:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.INFO)
