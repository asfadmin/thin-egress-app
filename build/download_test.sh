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
curl -s -v $APIROOT/$METADATA_FILE 2>&1 | grep redirect_uri
curl -s -v $APIROOT/$METADATA_FILE 2>&1 | grep -q redirect_uri
if [ $? -ne 0 ]; then echo "Could not verify redirect url was present"; exit 1; fi
echo " >>> PASSED"

echo " >>> Check that images are public..."
echo "  > curl -s --head $APIROOT/$BROWSE_FILE | grep 'Content-Type: image/jpeg'"
# curl -s --head $APIROOT/$BROWSE_FILE | grep 'Content-Type: image/jpeg'
# curl -s --head $APIROOT/$BROWSE_FILE | grep -q 'Content-Type: image/jpeg'
# if [ $? -ne 0 ]; then echo "Could not verify public images"; exit 1; fi
# echo " >>> PASSED"

echo " >>> Trying URS auth..."
echo "  > curl -s -v --cookie-jar /tmp/urscookie.txt $APIROOT/$METADATA_FILE | grep $METADATA_CHECK"
# First step is send auth to do URS... This will actually fail because of AWS...
curl --location-trusted -v --cookie-jar /tmp/urscookie.txt -u "$URS_USERNAME:$URS_PASSWORD" -L $APIROOT/$METADATA_FILE
# Now try again with jus tthe cookie jar.
curl -s -v --cookie-jar /tmp/urscookie.txt $APIROOT/$METADATA_FILE | grep $METADATA_CHECK
curl -s -v --cookie-jar /tmp/urscookie.txt $APIROOT/$METADATA_FILE | grep -q $METADATA_CHECK
if [ $? -ne 0 ]; then echo "Could not verify URS Auth'd Downloads"; exit 1; fi
echo " >>> PASSED"



