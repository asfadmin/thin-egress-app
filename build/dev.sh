#!/usr/bin/env bash
echo "starting looking for api gateways"

aws apigateway get-rest-apis --output=text --region ${AWS_DEFAULT_REGION}

API=$(aws apigateway get-rest-apis --query "items[?name=='${STACKNAME}-EgressGateway'].id" --output=text --region ${AWS_DEFAULT_REGION});
if [ -z $API ];  then exit 1; fi;
echo "woah, it worked!"
echo ${API}
