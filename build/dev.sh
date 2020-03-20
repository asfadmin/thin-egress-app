#!/usr/bin/env bash


API=$(aws apigateway get-rest-apis --query "items[?name=='${STACKNAME}-EgressGateway'].id" --output=text --region ${AWS_DEFAULT_REGION});
if [ -z $API ];  then exit 1; fi;
echo "woah, it worked!"
echo ${API}
