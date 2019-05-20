# Calculate the API Gateway path
API=$(aws apigateway get-rest-apis --query "items[?name=='${STACKNAME}-EgressGateway'].id" --output=text)
if [ -z $API ];  then echo "Could not figure out API Root URL"; exit 1; fi

APIROOT=$(echo "https://${API}.execute-api.us-east-1.amazonaws.com/DEV")
echo " >>> APIROOT is $APIROOT"

METADATA_FILE=METADATA_GRD_HS/SA/S1A_EW_GRDM_1SSV_20150802T074938_20150802T075036_007081_009A36_90B2.iso.xml
METADATA_CHECK='<gco:CharacterString>S1A_EW_GRDM_1SSV_20150802T074938_20150802T075036_007081_009A36_90B2.iso.xml</gco:CharacterString>'
BROWSE_FILE=BROWSE/SA/S1A_IW_GRDH_1SDH_20151205T093344_20151205T093417_008905_00CBDB_81B5.jpg

echo " >>> Checking for URS Redirect URL..."
echo "  > curl -s -v $APIROOT/$METADATA_FILE 2>&1 | grep redirect_uri "
curl -s -v $APIROOT/$METADATA_FILE 2>&1 &> /tmp/test1
cat /tmp/test1 | grep redirect_uri && cat /tmp/test1 | grep -q redirect_uri
if [ $? -ne 0 ]; then echo; echo " >> Could not verify redirect url was present (TEST 1) <<"; echo; exit 1; fi
echo " >>> Test 1 PASSED"

echo " >>> Check that images are public..."
echo "  > curl -s --head $APIROOT/$BROWSE_FILE | grep 'Content-Type: image/jpeg'"
curl -s --head $APIROOT/$BROWSE_FILE &> /tmp/test2
cat /tmp/test2 | grep 'Content-Type: image/jpeg' && cat /tmp/test2 | grep -q 'Content-Type: image/jpeg'
#if [ $? -ne 0 ]; then echo "Could not verify public images (TEST 2)"; exit 1; fi
if [ $? -ne 0 ]; then echo; echo " >> Could not verify public images (TEST 2) << "; echo; fi
#echo " >>> Test 2 PASSED"

echo " >>> Trying URS auth..."
echo "  > curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt $APIROOT/$METADATA_FILE | grep $METADATA_CHECK"
# First step is send auth to do URS... This will actually fail because of AWS...
echo " >>> Expect to see \`<Error><Code>InvalidArgument</Code><Message>...\` because U:P + Pre-Sign" 
curl -s --location-trusted --cookie-jar /tmp/urscookie.txt -u "$URS_USERNAME:$URS_PASSWORD" -L $APIROOT/$METADATA_FILE
echo ""
# Now try again with jus tthe cookie jar.
curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt $APIROOT/$METADATA_FILE 2>&1 &> /tmp/test3
cat /tmp/test3 | grep $METADATA_CHECK && cat /tmp/test3 | grep -q $METADATA_CHECK
if [ $? -ne 0 ]; then echo; echo " >> Could not verify URS Auth'd Downloads (TEST 3) << "; echo; exit 1; fi
echo " >>> Test 3 PASSED"

# Check for 404 on bad request
echo " >>> Testing 404 error return"
curl -sv $APIROOT/bad/url.ext 2>&1 &> /tmp/test4
cat /tmp/test4 | grep 'HTTP/1.1 404 Not Found' && cat /tmp/test4 | grep -q 'HTTP/1.1 404 Not Found'
if [ $? -ne 0 ]; then echo; echo " >> Could not verify 404 return (TEST 4) << "; echo; exit 1; fi
echo " >>> Test 4 PASSED"

# Check that range requests work
echo " >>> Testing Range requests "
echo " > curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt -r1035-1042 $APIROOT/$METADATA_FILE | grep \"^Codelist$\" "
curl -s -L -b /tmp/urscookie.txt -c /tmp/urscookie.txt -r1035-1042 $APIROOT/$METADATA_FILE 2>&1 &> /tmp/test5
cat /tmp/test5 | grep "^Codelist$" && cat /tmp/test5 | grep -q "^Codelist$"
if [ $? -ne 0 ]; then echo; echo " >> Could not verify Range request (TEST 5) << "; echo; exit 1; fi
echo " >>> Test 5 PASSED"



