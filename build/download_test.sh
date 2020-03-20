#!/bin/bash

# Calculate the API Gateway path
API=$(aws apigateway get-rest-apis --query "items[?name=='${STACKNAME}-EgressGateway'].id" --output=text)
#if [ -z $API ];  then echo "Could not figure out API Root URL"; exit 1; fi

if [ -z $DOMAIN_NAME ];  then API=$(aws apigateway get-rest-apis --query "items[?name=='${STACKNAME}-EgressGateway'].id" --output=text); APIROOT="https://${API}.execute-api.us-east-1.amazonaws.com/API"; else APIROOT="https://${DOMAIN_NAME}"; fi


#GATEWAYAPIROOT="https://${API}.execute-api.us-east-1.amazonaws.com/API"
#APIROOT="https://${DOMAIN_NAME-$GATEWAYAPIROOT}"
echo " >>> APIROOT is $APIROOT"

METADATA_FILE=SA/METADATA_GRD_HS/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml
METADATA_CHECK='<gco:CharacterString>S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.iso.xml</gco:CharacterString>'
BROWSE_FILE=SA/BROWSE/S1A_EW_GRDM_1SDH_20190206T190846_20190206T190951_025813_02DF0B_781A.jpg

# Fail Count
FC=0

# Check that we get a URS auth redirect for auth'd downloads
echo " >>> Checking for URS Redirect URL..."
echo "  > curl -s -v $APIROOT/$METADATA_FILE 2>&1 | grep redirect_uri "
curl -s -v $APIROOT/$METADATA_FILE 2>&1 &> /tmp/test1
grep redirect_uri /tmp/test1 && grep -q redirect_uri /tmp/test1
if [ $? -ne 0 ]; then echo; echo " >> Could not verify redirect url was present (TEST 1) <<"; echo; FC=$((FC+1)); else echo " >>> Test 1 PASSED"; fi

# Check that public files are returned without auth
echo " >>> Check that images are public..."
echo "  > curl -s -L --head $APIROOT/$BROWSE_FILE | grep 'Content-Type: image/jpeg'"
curl -s -L --head $APIROOT/$BROWSE_FILE &> /tmp/test2
grep 'Content-Type: image/jpeg' /tmp/test2 && grep -q 'Content-Type: image/jpeg' /tmp/test2
if [ $? -ne 0 ]; then echo; echo " >> Could not verify public images (TEST 2) << "; echo; FC=$((FC+1)); else echo " >>> Test 2 PASSED"; fi

# Validate that auth process is successful
echo " >>> Trying URS auth..."
echo "  > curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt $APIROOT/$METADATA_FILE | grep $METADATA_CHECK"
# First step is send auth to do URS... This will actually fail because of AWS...
echo " >>> Expect to see \`<Error><Code>InvalidArgument</Code><Message>...\` because U:P + Pre-Sign"
curl -s --location-trusted --cookie-jar /tmp/urscookie.txt -u "$URS_USERNAME:$URS_PASSWORD" -L $APIROOT/$METADATA_FILE
echo ""
# Now try again with jus tthe cookie jar.
curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt $APIROOT/$METADATA_FILE 2>&1 &> /tmp/test3
grep $METADATA_CHECK /tmp/test3 && grep -q $METADATA_CHECK /tmp/test3
if [ $? -ne 0 ]; then echo; echo " >> Could not verify URS Auth'd Downloads (TEST 3) << "; echo; FC=$((FC+1)); else echo " >>> Test 3 PASSED"; fi

# Check for 404 on bad request
echo " >>> Testing 404 error return"
curl -sv $APIROOT/bad/url.ext 2>&1 &> /tmp/test4
grep 'HTTP/1.1 404 Not Found' /tmp/test4 && grep -q 'HTTP/1.1 404 Not Found' /tmp/test4
if [ $? -ne 0 ]; then echo; echo " >> Could not verify 404 return (TEST 4) << "; echo; FC=$((FC+1)); else echo " >>> Test 4 PASSED"; fi

# Check that range requests work
echo " >>> Testing Range requests "
echo " > curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt -r1035-1042 $APIROOT/$METADATA_FILE | grep \"^Codelist$\" "
curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt -r1035-1042 $APIROOT/$METADATA_FILE 2>&1 &> /tmp/test5
grep "^Codelist$" /tmp/test5 && grep -q "^Codelist$" /tmp/test5
if [ $? -ne 0 ]; then echo; echo " >> Could not verify Range request (TEST 5) << "; echo; FC=$((FC+1)); else echo " >>> Test 5 PASSED"; fi

# Check that a bad cookie value causes URS redirect:
echo " >>> Testing invalid URS redirect "
echo " > curl -s -v --cookie 'urs-user-id=badusernamedne; urs-access-token=BLABLABLA' $APIROOT/$METADATA_FILE | grep redirect_uri"
curl -s -v --cookie 'urs-user-id=badusernamedne; urs-access-token=BLABLABLA' $APIROOT/$METADATA_FILE 2>&1 &> /tmp/test6
grep redirect_uri /tmp/test6 && grep -q redirect_uri /tmp/test6
if [ $? -ne 0 ]; then echo; echo " >> Could not verify bad auth redirect (TEST 6) << "; echo; FC=$((FC+1)); else echo " >>> Test 6 PASSED"; fi

# Check that approved users can access PRIVATE data:
echo " >>> Validating approved private data access"
echo " > curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt $APIROOT/PRIVATE/ACCESS/testfile | grep 'The file was successfully downloaded'"
curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt $APIROOT/PRIVATE/ACCESS/testfile 2>&1 &> /tmp/test7
cat /tmp/test7 && grep -q 'The file was successfully downloaded' cat /tmp/test7
if [ $? -ne 0 ]; then echo; echo " >> Could not verify PRIVATE access (TEST 7) << "; echo; FC=$((FC+1)); else echo " >>> Test 7 PASSED"; fi

# Check that approved users CAN'T access PRIVATE data they don't have access to:
echo " >>> Validating retriction of private data access"
echo " > curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt $APIROOT/PRIVATE/NOACCESS/testfile | grep 'HTTP/1.1 403 Forbidden'"
curl -sv -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt $APIROOT/PRIVATE/NOACCESS/testfile 2>&1 &> /tmp/test8
grep 'HTTP/1.1 403 Forbidden' /tmp/test8 && grep -q 'HTTP/1.1 403 Forbidden' /tmp/test8
if [ $? -ne 0 ]; then echo; echo " >> Could not verify PRIVATE access was restricted (TEST 8) << "; echo; FC=$((FC+1)); else echo " >>> TEST 8 PASSED"; fi

# Validating objects with prefix
echo " >>> Validating accessing objects with prefix's"
echo " > curl -s -L $APIROOT/SA/BROWSE/dir1/dir2/deepfile.txt | grep 'The file was successfully downloaded'"
curl -s -L $APIROOT/SA/BROWSE/dir1/dir2/deepfile.txt 2>&1 &> /tmp/test9
cat /tmp/test9 && grep -q 'The file was successfully downloaded' /tmp/test9
if [ $? -ne 0 ]; then echo; echo " >> Could not verify prefixed file access (TEST9) << "; echo; FC=$((FC+1)); else echo " >>> TEST 9 PASSED"; fi

# Build Summary
if [ $FC -le 0 ]; then
   echo " >>> All Tests Passed!"
   echo '{ "schemaVersion": 1, "label": "Tests", "message": "All Tests Passed", "color": "success" }' > /tmp/testresults.json
elif [ $FC -lt 3 ]; then
   echo " >>> Some Tests Failed"
   echo '{ "schemaVersion": 1, "label": "Tests", "message": "'$FC'/9 Tests Failed ⚠️", "color": "important" }' > /tmp/testresults.json
else
   echo " >>> TOO MANY TEST FAILURES! "
   echo '{ "schemaVersion": 1, "label": "Tests", "message": "'$FC'/9 Tests Failed ☠", "color": "critical" }' > /tmp/testresults.json
fi

# Upload test results
aws s3 cp --metadata-directive REPLACE --cache-control no-cache \
          --expires '2016-06-14T00:00:00Z' --content-type 'application/json' \
          /tmp/testresults.json s3://asf.public.code/thin-egress-app/ --acl public-read

if [ $FC -gt 0 ]; then echo "Angry Exit!"; exit 1; fi
