import argparse
import logging
import re
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from typing import List

import boto3

log = logging.getLogger(__name__)

VERSION_PATTERN = re.compile(r"tea-(code|cloudformation|dependencylayer|terraform|)-(build\..+)\.(zip|yaml)")


@dataclass
class TeaVersion:
    id: str
    code_uri: str
    depedency_layer_uri: str
    template_uri: str
    terraform_uri: str

    @property
    def code_url(self) -> str:
        return _to_s3_url(self.code_uri)

    @property
    def depedency_layer_url(self) -> str:
        return _to_s3_url(self.depedency_layer_uri)

    @property
    def template_url(self) -> str:
        return _to_s3_url(self.template_uri)

    @property
    def terraform_url(self) -> str:
        return _to_s3_url(self.terraform_uri)


class TeaVersionResolver:
    def __init__(self, session: boto3.Session):
        self.session = session

    def get_versions(self) -> List[TeaVersion]:
        client = self.session.client("s3")

        paginator = client.get_paginator("list_objects_v2")

        versions = defaultdict(dict)

        for result in paginator.paginate(
            Bucket="asf.public.code",
            Prefix="thin-egress-app/tea-"
        ):
            bucket = result["Name"]

            for entry in result.get("Contents", ()):
                key = entry["Key"]

                m = VERSION_PATTERN.match(key, pos=len("thin-egress-app/"))
                if not m:
                    continue

                component, id, ext = m.groups()
                versions[id][component] = f"s3://{bucket}/{key}"

        versions = [
            TeaVersion(
                name,
                entry["code"],
                entry["dependencylayer"],
                entry["cloudformation"],
                entry["terraform"]
            )
            for name, entry in versions.items()
            if set(entry.keys()) == {"code", "cloudformation", "dependencylayer", "terraform"}
        ]

        return sorted(versions, key=_sort_key, reverse=True)


def main(args=None):
    parser = get_parser()

    parsed_args = parser.parse_args(args)
    handle_args(parsed_args)


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()

    configure_parser(parser)

    return parser


def configure_parser(parser: argparse.ArgumentParser):
    parser.add_argument("--profile", help="AWS profile")


def handle_args(args: argparse.Namespace):
    list_versions(
        profile_name=args.profile
    )


def list_versions(profile_name: str):
    session = boto3.Session(profile_name=profile_name)

    resolver = TeaVersionResolver(session)
    versions = resolver.get_versions()

    log.info("Available TEA versions:")
    for version in versions:
        log.info("    %s", version.id)


def _sort_key(v: TeaVersion):
    _, *id = v.id.split(".")
    try:
        return len(id), [int(v) for v in id]
    except ValueError:
        return len(id), id


def _to_s3_url(s3_uri: str):
    parse_result = urllib.parse.urlparse(s3_uri)

    return f"https://{parse_result.netloc}.s3.amazonaws.com{parse_result.path}"
