import os
from datetime import datetime

import boto3
from rain_api_core.general_util import get_log

log = get_log()

TEA_LAMBDA_NAME = os.getenv("TEA_LAMBDA_NAME")


def lambda_handler(event, context):
    del event

    log.info("teabumper!")

    client = boto3.client("lambda")

    egress_env = client.get_function_configuration(
        FunctionName=TEA_LAMBDA_NAME,
    ).get("Environment") or {"Variables": {}}

    egress_env["Variables"].update({
        "BUMP": f"{str(datetime.utcnow())}, {context.aws_request_id}"
    })

    log.debug("envvar for %s: %s", TEA_LAMBDA_NAME, egress_env["Variables"])
    response = client.update_function_configuration(
        FunctionName=TEA_LAMBDA_NAME,
        Environment=egress_env
    )
    log.debug(response)
