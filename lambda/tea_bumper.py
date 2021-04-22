import json
import boto3
import urllib.request
import os

from rain_api_core.general_util import get_log
log = get_log()

client = boto3.client('lambda')


def lambda_handler(event, context):

    log.info('teabumper!')

    response = client.get_function_configuration(
        FunctionName=os.getenv('TEA_LAMBDA_NAME'),

    )
    log.info(f"cfg for {os.getenv('TEA_LAMBDA_NAME')}: {response}")
    '''response = client.update_function_configuration(
        FunctionName=os.getenv('TEA_LAMBDA_NAME'),
        Environment={
            'Variables': {
                'env_var': 'hello'
            }
        }
    )
    log.info(response)'''


def version():
    log.info("Got a version request!")
    return json.dumps({'version_id': '<BUILD_ID>'})
