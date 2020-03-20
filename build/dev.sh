#!/usr/bin/env bash
echo "starting looking for api gateways"

echo "domainname: ${DOMAIN_NAME}, aws region: ${AWS_DEFAULT_REGION}, stackname: ${STACKNAME}"

aws apigateway get-rest-apis --output=text --region ${AWS_DEFAULT_REGION}

if [ -z $DOMAIN_NAME ];  then echo "we don't have domain name, looking it up"; API=$(aws apigateway get-rest-apis --query "items[?name=='${STACKNAME}-EgressGateway'].id" --output=text --region ${AWS_DEFAULT_REGION}); echo ${API}; APIROOT="https://${API}.execute-api.us-east-1.amazonaws.com/API"; else APIROOT="https://${DOMAIN_NAME}"; fi

echo "API: ${API}"
echo "APIROOT: ${APIROOT}"

if [ -z $API ]; then  echo "we don't have API"; exit 1; fi;
echo "woah, it worked!"
echo ${API}
