import argparse
import base64
import json
import logging
import textwrap
import urllib.parse
from typing import List, Optional

import boto3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tea_cli.commands.list_versions import TeaVersion, TeaVersionResolver
from tea_cli.deploy import (
    Bucket,
    BucketObject,
    BucketObjectCopy,
    CloudFormationStack,
    Deployer,
    Inputs,
    Resource,
    Secret,
    Step
)

log = logging.getLogger(__name__)


def main(args=None):
    parser = get_parser()

    parsed_args = parser.parse_args(args)
    handle_args(parsed_args)


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()

    configure_parser(parser)

    return parser


def configure_parser(parser: argparse.ArgumentParser):
    parser.add_argument("--stack-name", help="CloudFormation stack name")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--edl-uid", help="EDL app uid", dest="edl_uid")
    parser.add_argument("--edl-pass", help="EDL app password", dest="edl_password")
    parser.add_argument("--edl-client-id", help="EDL app client ID", dest="edl_client_id")


def handle_args(args: argparse.Namespace):
    quick_deploy(
        stack_name=args.stack_name,
        profile_name=args.profile,
        edl_uid=args.edl_uid,
        edl_password=args.edl_password,
        edl_client_id=args.edl_client_id
    )


def quick_deploy(
    stack_name: str,
    profile_name: str,
    edl_uid: str = None,
    edl_password: str = None,
    edl_client_id: str = None,
):
    session = boto3.Session(profile_name=profile_name)
    inputs = {
        "stack_name": stack_name,
        "edl_uid": edl_uid,
        "edl_password": edl_password,
        "edl_client_id": edl_client_id
    }
    deployer = Deployer(session, inputs)

    # 1. Create secrets
    deployer.deploy_step(UrsSecretStep())
    deployer.deploy_step(JwtSecretStep())

    # 2. Create buckets
    deployer.deploy_step(BucketsStep())

    # 3. Copy source from asf public bucket
    deployer.deploy_step(SourceCodeStep())

    # 4. Upload bucket map
    deployer.deploy_step(BucketMapStep())

    # 5. Upload test files
    deployer.deploy_step(TestFilesStep())

    # 6. Check for NGAP VPC config parameters
    # 7. Deploy CloudFormation
    deployer.deploy_step(CloudFormationStep())
    # 8. Validate deployment


def get_tea_version(session: boto3.Session) -> Optional[TeaVersion]:
    resolver = TeaVersionResolver(session)

    log.debug("Checking for available releases")
    versions = resolver.get_versions()

    if not versions:
        log.error("No TEA releases available!")
        return

    default_version = versions[0]

    log.info("Latest available releases:")
    for version in versions[:5]:
        log.info("    %s", version.id)

    selected = input(f"Version to deploy [{default_version.id}]: ").strip() or default_version.id

    selected_version = next(
        (version for version in versions if version.id == selected),
        None
    )
    if not selected_version:
        log.error("Invalid version specified")

    return selected_version


class UrsSecretStep(Step):
    def get_name(self) -> str:
        return "URS secret"

    def get_resources(
        self,
        session: boto3.Session,
        inputs: Inputs,
    ) -> List[Resource]:
        stack_name = inputs.get_argument("stack_name", "Stack Name")
        secret_name = f"urs_creds_for_{stack_name}"

        inputs.set_argument("urs_secret_name", secret_name)

        return [
            Secret(
                secret_name,
                f"URS creds for TEA {stack_name} app",
                self.get_secret_string(inputs)
            )
        ]

    def get_secret_string(self, inputs: Inputs) -> str:
        edl_uid = inputs.get_argument("edl_uid", "EDL App UID")
        edl_password = inputs.get_secret("edl_password", "EDL App Password")
        edl_client_id = inputs.get_argument("edl_client_id", "EDL App Client ID")

        urs_auth = base64.b64encode(f"{edl_uid}:{edl_password}".encode())

        return json.dumps(
            {
                "UrsAuth": urs_auth.decode(),
                "UrsId": edl_client_id
            },
            indent=2
        )


class JwtSecretStep(Step):
    def get_name(self) -> str:
        return "JWT secret"

    def get_resources(
        self,
        session: boto3.Session,
        inputs: Inputs,
    ) -> List[Resource]:
        stack_name = inputs.get_argument("stack_name", "Stack Name")
        secret_name = f"jwt_creds_for_{stack_name}"

        inputs.set_argument("jwt_secret_name", secret_name)

        return [
            Secret(
                secret_name,
                f"RS256 keys for TEA {stack_name} app JWT cookies",
                self.get_secret_string()
            )
        ]

    def get_secret_string(self) -> str:
        log.info("Creating JWT Key")

        # TODO(reweeden): Add option to reuse previously generated secret
        # Write to files /tmp/${STACKNAME}-jwt.key and /tmp/${STACKNAME}-jwt.key.pub
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return json.dumps(
            {
                "rsa_priv_key": base64.b64encode(private_pem).decode(),
                "rsa_pub_key": base64.b64encode(public_pem).decode()
            },
            indent=2
        )


class BucketsStep(Step):
    def get_name(self) -> str:
        return "Buckets"

    def get_resources(
        self,
        session: boto3.Session,
        inputs: Inputs,
    ) -> List[Resource]:
        stack_name = inputs.get_argument("stack_name", "Stack Name")

        buckets = []
        for name in ("config", "code", "restricted", "public"):
            bucket_name = f"{stack_name}-{name}"
            inputs.set_argument(f"{name}_bucket", bucket_name)
            buckets.append(Bucket(bucket_name))

        return buckets


class SourceCodeStep(Step):
    def get_name(self) -> str:
        return "Source code"

    def get_resources(
        self,
        session: boto3.Session,
        inputs: Inputs,
    ) -> List[Resource]:
        tea_version = get_tea_version(session)
        if tea_version is None:
            return

        inputs.set_state("tea_version", tea_version)

        stack_name = inputs.get_argument("stack_name", "Stack Name")
        code_bucket = inputs.get_argument(
            "code_bucket",
            "Code Bucket",
            f"{stack_name}-code"
        )

        resources = []
        for output_name, uri in (
            ("code_key", tea_version.code_uri),
            ("depedency_layer_key", tea_version.depedency_layer_uri)
        ):
            parse_result = urllib.parse.urlparse(uri)
            source_bucket = parse_result.netloc
            key = parse_result.path[1:]

            inputs.set_argument(output_name, key)

            resources.append(
                BucketObjectCopy(
                    source_bucket,
                    key,
                    code_bucket,
                    key
                )
            )

        return resources


class BucketMapStep(Step):
    def get_name(self) -> str:
        return "Bucket map"

    def get_resources(
        self,
        session: boto3.Session,
        inputs: Inputs
    ) -> List[Resource]:
        stack_name = inputs.get_argument("stack_name", "Stack Name")
        config_bucket = inputs.get_argument(
            "config_bucket",
            "Config Bucket",
            f"{stack_name}-config"
        )

        return [
            BucketObject(
                config_bucket,
                "bucket_map.yaml",
                textwrap.dedent(
                    """
                    MAP:
                      pub: public
                      res: restricted
                    PUBLIC_BUCKETS:
                      public: "Public, no EDL"
                    """
                ).strip().encode()
            )
        ]


class TestFilesStep(Step):
    def get_name(self) -> str:
        return "Test files"

    def get_resources(
        self,
        session: boto3.Session,
        inputs: Inputs,
    ) -> List[Resource]:
        stack_name = inputs.get_argument("stack_name", "Stack Name")
        public_bucket = inputs.get_argument(
            "public_bucket",
            "Public Bucket",
            f"{stack_name}-public"
        )
        restricted_bucket = inputs.get_argument(
            "restricted_bucket",
            "Restricted Bucket",
            f"{stack_name}-restricted"
        )

        return [
            BucketObject(
                public_bucket,
                "test.txt",
                b"this is a public file"
            ),
            BucketObject(
                restricted_bucket,
                "test.txt",
                b"this is a restricted file"
            )
        ]


class CloudFormationStep(Step):
    def get_name(self) -> str:
        return "CloudFormation Stack"

    def get_resources(
        self,
        session: boto3.Session,
        inputs: Inputs,
    ) -> List[Resource]:
        tea_version: Optional[TeaVersion] = inputs.get_state("tea_version")
        if tea_version is None:
            tea_version = get_tea_version(session)
        if tea_version is None:
            return []

        stack_name = inputs.get_argument("stack_name", "Stack Name")
        maturity = inputs.get_argument("maturity", "Maturity", "DEV")
        config_bucket = inputs.get_argument(
            "config_bucket",
            "Config Bucket",
            f"{stack_name}-config"
        )
        code_bucket = inputs.get_argument(
            "code_bucket",
            "Code Bucket",
            f"{stack_name}-code"
        )
        urs_secret_name = inputs.get_argument(
            "urs_secret_name",
            "URS Secret Name",
            f"urs_creds_for_{stack_name}"
        )
        jwt_secret_name = inputs.get_argument(
            "jwt_secret_name",
            "JWT Secret Name",
            f"jwt_creds_for_{stack_name}"
        )
        depedency_layer_key = inputs.get_argument(
            "depedency_layer_key",
            "Dependency Layer S3 Key",
            urllib.parse.urlparse(tea_version.depedency_layer_uri).path[1:]
        )
        code_key = inputs.get_argument(
            "code_key",
            "Lambda Code S3 Key",
            urllib.parse.urlparse(tea_version.code_uri).path[1:]
        )
        auth_base_url = inputs.get_argument(
            "auth_base_url",
            "EDL Base URL",
            "https://uat.urs.earthdata.nasa.gov"
        )

        client = session.client("ec2")

        vpc_parameters = {}
        vpcs = client.describe_vpcs(
            Filters=[{
                "Name": "tag:Name",
                "Values": ["Application VPC"]
            }]
        ).get("Vpcs") or []

        if vpcs:
            if len(vpcs) > 1:
                # TODO(reweeden): Select the VPC to use on CL
                raise NotImplementedError()

            vpc_id = vpcs[0]["VpcId"]

            subnets = client.describe_subnets(
                Filters=[
                    {
                        "Name": "tag:Name",
                        "Values": ["Private*"]
                    },
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id]
                    }
                ]
            ).get("Subnets") or []
            security_groups = client.describe_security_groups(
                Filters=[
                    {
                        "Name": "tag:Name",
                        "Values": ["Application Default*"]
                    },
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id]
                    }
                ]
            ).get("SecurityGroups") or []

            vpc_parameters = {
                "PrivateVPC": vpc_id,
                "VPCSecurityGroupIDs": ",".join(group["GroupId"] for group in security_groups),
                "VPCSubnetIDs": ",".join(subnet["SubnetId"] for subnet in subnets),
            }

        return [
            CloudFormationStack(
                stack_name,
                template_url=tea_version.template_url,
                parameters={
                    "AuthBaseUrl": auth_base_url,
                    "BucketMapFile": "bucket_map.yaml",
                    "BucketnamePrefix": f"{stack_name}-",
                    "ConfigBucket": config_bucket,
                    "EnableApiGatewayLogToCloudWatch": "False",
                    "JwtAlgo": "RS256",
                    "JwtKeySecretName": jwt_secret_name,
                    "LambdaCodeDependencyArchive": depedency_layer_key,
                    "LambdaCodeS3Bucket": code_bucket,
                    "LambdaCodeS3Key": code_key,
                    "LambdaTimeout": "6",
                    "Loglevel": "INFO",
                    "Maturity": maturity,
                    "PermissionsBoundaryName": "NGAPShRoleBoundary",
                    "SessionTTL": "168",
                    "StageName": "API",
                    "URSAuthCredsSecretName": urs_secret_name,
                    "UseReverseBucketMap": "False",
                    **vpc_parameters
                },
                capabilities=["CAPABILITY_NAMED_IAM"]
            )
        ]
