import getpass
import logging
from abc import ABC, abstractmethod
from typing import List

import boto3

log = logging.getLogger(__name__)


class Resource(ABC):
    @abstractmethod
    def deploy(self, session: boto3.Session):
        pass

    def get_name(self) -> str:
        return self.__class__.__name__


class Bucket(Resource):
    def __init__(self, name: str):
        self.name = name

    def deploy(self, session: boto3.Session):
        client = session.client("s3")

        try:
            client.head_bucket(Bucket=self.name)
            log.info("Bucket exists: %s", self.name)
        except client.exceptions.ClientError:
            log.info(">> Creating bucket: %s", self.name)
            client.create_bucket(
                Bucket=self.name,
                CreateBucketConfiguration={
                    "LocationConstraint": session.region_name
                }
            )


class BucketObject(Resource):
    def __init__(self, bucket: str, key: str, body: bytes):
        self.bucket = bucket
        self.key = key
        self.body = body

    def deploy(self, session: boto3.Session):
        client = session.client("s3")

        try:
            client.head_object(
                Bucket=self.bucket,
                Key=self.key
            )
            log.info("Object exists s3://%s/%s", self.bucket, self.key)
        except client.exceptions.ClientError:
            log.info(">> Creating object s3://%s/%s", self.bucket, self.key)
            client.put_object(
                Bucket=self.bucket,
                Key=self.key,
                Body=self.body
            )


class BucketObjectCopy(Resource):
    def __init__(
        self,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str
    ):
        self.src_bucket = src_bucket
        self.src_key = src_key
        self.dst_bucket = dst_bucket
        self.dst_key = dst_key

    def deploy(self, session: boto3.Session):
        client = session.client("s3")

        try:
            client.head_object(
                Bucket=self.dst_bucket,
                Key=self.dst_key
            )
            log.info("Object exists s3://%s/%s", self.dst_bucket, self.dst_key)
        except client.exceptions.ClientError:
            # TODO(reweeden): Check for 404 error
            log.info(
                ">> Copying s3://%s/%s to s3://%s/%s",
                self.src_bucket,
                self.src_key,
                self.dst_bucket,
                self.dst_key
            )

            client.copy(
                {
                    "Bucket": self.src_bucket,
                    "Key": self.src_key,
                },
                self.dst_bucket,
                self.dst_key
            )


class CloudFormationStack(Resource):
    def __init__(
        self,
        stack_name: str,
        template_body: str = None,
        template_url: str = None,
        parameters: dict = {},
        capabilities: list = [],
    ):
        self.stack_name = stack_name
        if (template_body is None) is (template_url is None):
            raise ValueError(
                "Must provide exactly one of 'template_body' or 'template_url'"
            )
        self.template_body = template_body
        self.template_url = template_url
        self.parameters = parameters
        self.capabilities = capabilities

    def _get_parameter_list(self) -> List[dict]:
        return [
            {
                "ParameterKey": k,
                "ParameterValue": v
            }
            for k, v in self.parameters.items()
        ]

    def deploy(self, session: boto3.Session):
        client = session.client("cloudformation")

        kwargs = {
            "StackName": self.stack_name,
            "Parameters": self._get_parameter_list(),
            "Capabilities": self.capabilities,
        }

        if self.template_body is not None:
            kwargs["TemplateBody"] = self.template_body
        if self.template_url is not None:
            kwargs["TemplateURL"] = self.template_url

        if self._has_stack(client):
            log.info(">> Updating cloudformation stack %s", self.stack_name)
            client.update_stack(**kwargs)
            client.get_waiter("stack_update_complete").wait(StackName=self.stack_name)
        else:
            log.info(">> Creating cloudformation stack %s", self.stack_name)
            client.create_stack(**kwargs)
            client.get_waiter("stack_create_complete").wait(StackName=self.stack_name)

    def _has_stack(self, client):
        # From the AWS CLI implementation
        # https://github.com/aws/aws-cli/blob/540cc0e290d9178be0efcfb8f2a8d4b6648005f0/awscli/customizations/cloudformation/deployer.py#L38
        try:
            resp = client.describe_stacks(StackName=self.stack_name)
            if len(resp["Stacks"]) != 1:
                return False

            stack = resp["Stacks"][0]
            return stack["StackStatus"] != "REVIEW_IN_PROGRESS"

        except client.exceptions.ClientError as e:
            msg = str(e)

            if f"Stack with id {self.stack_name} does not exist" in msg:
                log.debug("Stack with id %s does not exist", self.stack_name)
                return False
            else:
                log.debug("Unable to get stack details.", exc_info=e)
                raise e


class Secret(Resource):
    def __init__(self, name: str, description: str, secret_string: str):
        self.name = name
        self.description = description
        self.secret_string = secret_string

    def deploy(self, session: boto3.Session):
        client = session.client("secretsmanager")

        try:
            client.describe_secret(SecretId=self.name)
        except client.exceptions.ResourceNotFoundException:
            log.info(">> Creating secret %s", self.name)
            client.create_secret(
                Name=self.name,
                Description=self.description,
                SecretString=self.secret_string,
            )
        else:
            log.info(">> Updating secret %s", self.name)
            client.update_secret(
                SecretId=self.name,
                Description=self.description,
                SecretString=self.secret_string
            )


class Inputs:
    def __init__(self, inputs: dict, state: dict):
        self.inputs = inputs
        self.state = state

    def get_argument(self, name: str, prompt: str, default=None):
        value = self.inputs.get(name)
        if value is None:
            if default is None:
                full_prompt = f"{prompt}: "
            else:
                full_prompt = f"{prompt} [{default}]: "
            value = input(full_prompt).strip() or default

        self.inputs[name] = value

        return value

    def get_secret(self, name: str, prompt: str, default=None):
        value = self.inputs.get(name)
        if value is None:
            if default is None:
                full_prompt = f"{prompt}: "
            else:
                full_prompt = f"{prompt} [{default}]: "
            value = getpass.getpass(full_prompt).strip() or default

        self.inputs[name] = value

        return value

    def set_argument(self, name: str, value: str):
        self.inputs[name] = value

    def get_state(self, name: str, default=None):
        return self.state.get(name, default)

    def set_state(self, name: str, value):
        self.state[name] = value


class Step(ABC):
    @abstractmethod
    def get_resources(
        self,
        session: boto3.Session,
        inputs: Inputs
    ) -> List[Resource]:
        pass

    def get_name(self) -> str:
        return self.__class__.__name__


class Deployer:
    def __init__(self, session: boto3.Session, inputs: dict = {}):
        self.session = session
        self.inputs_dict = inputs
        self.state_dict = {}
        self.inputs = Inputs(self.inputs_dict, self.state_dict)

    def deploy_step(self, step: Step) -> List[Resource]:
        if self.confirm_step(step):
            resources = step.get_resources(
                self.session,
                self.inputs
            )
            for resource in resources:
                resource.deploy(self.session)

            return resources

        return []

    def confirm_step(self, step: Step) -> bool:
        name = step.get_name()
        return input(f"Deploy {name}? [Y/n]: ")[:1].lower() != "n"
