#!/bin/bash

#  DEPLOY: 
#  ./depoy.sh  --stack-name=<STACK-NAME> \
#              --aws-profile=<AWS-PROFILE-NAME> \
#              --bastion="<SSM-BASTION-NAME>" \
#              --key-file=<LOCAL-PATH-TO-YOUR-PRIVATE-KEY> \
#              --uid=<EDL-APP-UID> \
#              --client-id=<EDL-APP-CLIENT-ID> \
#              --pass='<EDL-APP-PASSWORD>' \
#              --region-name="aws-region-value" \
#              --maturity=<SBX|DEV|SIT|INT|UAT|TEST|PROD>  \
#              --edl-user-creds='<EDL-USERNAME>:<EDL-PASSWORD>' 
#
#        -a|--aws-profile     AWS Profile (from ~/.aws/credentials)
#        -b|--bastion         SSM Bastion name ("NGAP SSH Bastion"?)
#        -c|--client-id       EDL App Client ID
#        -e|--edl-user-creds  EDL USER credentials (For Validating DL's)
#        -k|--key-file        ssh key for connecting to SSM Bastion
#        -m|--maturity        Account/EDL Matuirty (SBX|SIT|UAT|PROD)
#        -p|--pass            EDL App Password
#        -r|--region-name     AWS Region to deploy to (Default: us-west-w)
#        -s|--stack-name      The name of the stack to be deployed.
#        -u|--uid             EDL App UID 
#
#  DESTROY:
#  ./depoy.sh  --destroy-stack=<STACK-NAME> \
#              --aws-profile=<AWS-PROFILE-NAME> \
#              --region-name="aws-region-value" \
#
#        --destroy-stack      Stack name to destory all the parts we created
#        -a|--aws-profile     AWS Profile (from ~/.aws/credentials)
#        -r|--region-name     AWS Region to deploy to (Default: us-west-w)

# Pass Options
for i in "$@"
do
case $i in
    -s=*|--stack-name=*)
    STACKNAME="${i#*=}"
    ;;    

    --destroy-stack=*)
    DESTROY="${i#*=}"
    ;;

    -a=*|--aws-profile=*)
    AWSPROFILE="${i#*=}"
    ;;

    -k=*|--key-file=*)
    KEYFILE="${i#*=}"
    ;;

    -u=*|--uid=*)
    EDLUID="${i#*=}"
    ;;
    
    -p=*|--pass=*)
    EDLPASS="${i#*=}"
    ;;

    -c=*|--client-id=*)
    CLIENTID="${i#*=}"
    ;;

    -b=*|--bastion=*)
    BASTIONNAME="${i#*=}"
    ;;

    -r=*|--region-name=*)
    AWSREGION="${i#*=}"
    ;;

    -m=*|--maturity=*)
    MATURITY="${i#*=}"
    ;;

    -e=*|--edl-user-creds=*)
    EDLUSER="${i#*=}"
    ;;

    *)
    echo "Invalid Argument '${i}'" && exit 1
            # unknown option
    ;;
esac
done

case $MATURITY in 
    [dD][eE][vV]|[sS][bB][xX])
    EDL="sbx.urs"
    MAT="DEV" 
    ;;
    [iI][nN][tT]|[sS][iI][tT])
    EDL="sit.urs"
    MAT="INT"
    ;;
    [tT][eE][sS][tT]|[uU][aA][tT])
    EDL="uat.urs"
    MAT="TEST"
    echo Maturty is $EDL/$MAT
    ;;
    [pP][rR][oO][dD])
    EDL="urs"
    MAT="PROD"
    ;;
    *)
    EDL="uat.urs"
    MAT="DEV"
    ;;
esac

if [ -z "$AWSREGION" ]; then
   AWSREGION=us-west-2
   echo ">> Deploying to default us-west-2, override with --region-name"
fi

if [[ -z "$KEYFILE" || -z "$BASTIONNAME" ]]; then
   echo ">> Skipping post deployment checks, try supplying --key-file/--bastion"
fi

if [[ -z "$EDLUID" || -z "$EDLPASS" || -z "$CLIENTID" ]]; then
   echo ">> Skipping EDL configurations, try supplying --uid/--pass/--client-id"
   NOEDL=True
fi

if [ -z "$AWSPROFILE" ]; then
   AWSENV="--region=$AWSREGION"
else
   AWSENV="--profile=$AWSPROFILE --region=$AWSREGION"
fi

# Check for DESTUCTION
if [ ! -z "$DESTROY" ]; then
   echo ">> ⚠️ ⚠️ ⚠️  DESTROYING STACK $DESTROY ⚠️ ⚠️ ⚠️ "

   echo ">> ☠️  Destroying Cloudformation Stack ..."
   aws $AWSENV cloudformation delete-stack --stack-name ${DESTROY}

   echo ">> ☠️  Destroying Secrets ..."
   aws $AWSENV secretsmanager delete-secret --secret-id jwt_creds_for_${DESTROY}
   aws $AWSENV secretsmanager delete-secret --secret-id urs_creds_for_${DESTROY}

   echo ">> ☠️  Destroying Buckets ..."
   for i in ${DESTROY}-config ${DESTROY}-code ${DESTROY}-restricted ${DESTROY}-public; do
      aws $AWSENV s3 rm --recursive s3://$i
      aws $AWSENV s3 rb s3://$i 
   done 

   echo ">> 🎉 Purge Complete."
   
   exit 0
fi 

# Check Input
if [ -z "$STACKNAME" ]; then
   rand_id=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | fold -w 6 | head -n 1 )
   STACKNAME="my-tea-${rand_id}"
   echo ">> no Stack Name provided, using $STACKNAME"
else
   echo ">> Building Stack $STACKNAME"
fi


###  Create Secrets
jwt_secret_file="/tmp/${STACKNAME}-jwt.json"
jwt_key_file="/tmp/${STACKNAME}-jwt.key"
urs_secret_file="/tmp/${STACKNAME}-urs.json"
jwt_secret_name="jwt_creds_for_${STACKNAME}"
urs_secret_name="urs_creds_for_${STACKNAME}"


touch $jwt_secret_file && touch $urs_secret_file
chmod 600 $jwt_secret_file $urs_secret_file

# write out URS secret
UrsAuth=$(echo -n "$EDLUID:$EDLPASS" | base64)
UrsId="$CLIENTID"
cat << EOL > $urs_secret_file
{
    "UrsAuth": "$UrsAuth",
    "UrsId": "$UrsId"
}
EOL

# Check if this is create/update
secret_arn=$(aws $AWSENV secretsmanager describe-secret \
                                 --secret-id ${urs_secret_name} \
                                 --query "ARN" --output=text 2>&1 \
                                 | grep -v ResourceNotFoundException)
if [ -z "$secret_arn" ]; then
   echo ">> Creating URS Secret ${urs_secret_name}"
   aws $AWSENV secretsmanager create-secret --name ${urs_secret_name} \
       --description "URS creds for TEA ${STACKNAME} app" \
       --secret-string file://${urs_secret_file}
else
   echo ">> Updating URS Secret ${urs_secret_name}"
   aws $AWSENV secretsmanager update-secret --secret-id ${urs_secret_name} \
       --description "URS creds for TEA ${STACKNAME} app" \
       --secret-string file://${urs_secret_file}
fi

# write out JWT secret
if [ ! -f ${jwt_key_file} ]; then 
   echo ">> Creating JWT Key ${jwt_key_file}"
   ssh-keygen -t rsa -b 4096 -m PEM -N '' -f $jwt_key_file 
   chmod 600 ${jwt_key_file} ${jwt_key_file}.pub
fi
rsa_priv_key=$(openssl base64 -in $jwt_key_file -A)
rsa_pub_key=$(openssl base64 -in ${jwt_key_file}.pub -A)
cat << EOL > $jwt_secret_file
{
    "rsa_priv_key": "$rsa_priv_key",
    "rsa_pub_key":  "$rsa_pub_key"
}
EOL

# Check if this is create/update
secret_arn=$(aws $AWSENV secretsmanager describe-secret \
                                 --secret-id ${jwt_secret_name} \
                                 --query "ARN" --output=text 2>&1 \
                                 | grep -v ResourceNotFoundException)
if [ -z "$secret_arn" ]; then
   echo ">> Creating JWT Secret ${jwt_secret_name}"
   aws $AWSENV secretsmanager create-secret --name ${jwt_secret_name} \
       --description "RS256 keys for TEA ${STACKNAME} app JWT cookies" \
       --secret-string file://${jwt_secret_file}
else
   echo ">> Updating JWT Secret ${jwt_secret_name}"
   aws $AWSENV secretsmanager update-secret --secret-id ${jwt_secret_name} \
       --description "RS256 keys for TEA ${STACKNAME} app JWT cookies" \
       --secret-string file://${jwt_secret_file}
fi

# Buckets
config_bucket="${STACKNAME}-config"
code_bucket="${STACKNAME}-code"
restricted_bucket="${STACKNAME}-restricted"
public_bucket="${STACKNAME}-public"

for i in $config_bucket $code_bucket $restricted_bucket $public_bucket; do
   echo ">> Checking if S3 Bucket $i exists"
   aws $AWSENV s3api head-bucket --bucket "$i" 2>/dev/null
   if [ $? -gt 0 ]; then
      echo ">> creating bucket $i"
      aws $AWSENV s3 mb s3://$i 2>/dev/null
   fi
done
      

# Find the stuff we need to download
code_zip=$(aws $AWSENV s3api list-objects --bucket asf.public.code \
                                          --prefix "thin-egress-app/tea-code-build" \
                                          --query "reverse(sort_by(Contents,&LastModified))" \
                                          --output=text | head -1 | xargs -n1 | grep zip)
layer_zip=$(aws $AWSENV s3api list-objects --bucket asf.public.code \
                                           --prefix "thin-egress-app/tea-dependencylayer-build" \
                                           --query "reverse(sort_by(Contents,&LastModified))" \
                                           --output=text | head -1 | xargs -n1 | grep zip)
cf_yaml=$(aws $AWSENV s3api list-objects --bucket asf.public.code \
                                         --prefix "thin-egress-app/tea-cloudformation-build" \
                                         --query "reverse(sort_by(Contents,&LastModified))" \
                                         --output=text | head -1 | xargs -n1 | grep yaml)
cf_yaml_name=$(echo $cf_yaml | cut -d "/" -f 2)

# Copy/Downloads the build files
echo ">> Ensuring we have the latest build artifacts..."
aws $AWSENV s3 ls s3://$code_bucket/$code_zip 2>/dev/null
if [ $? -gt 0 ]; then
   aws $AWSENV s3 cp s3://asf.public.code/$code_zip s3://$code_bucket/$code_zip
else
   echo ">> Skipping upload of existing $code_zip to s3://$code_bucket/$code_zip"  
fi
aws $AWSENV s3 ls s3://$code_bucket/$layer_zip 2>/dev/null
if [ $? -gt 0 ]; then
   aws $AWSENV s3 cp s3://asf.public.code/$layer_zip s3://$code_bucket/$layer_zip
else
   echo ">> Skipping upload of existing $layer_zip to s3://$code_bucket/$layer_zip"
fi
if [ ! -f "/tmp/$cf_yaml_name" ]; then 
   aws $AWSENV s3 cp s3://asf.public.code/$cf_yaml /tmp/$cf_yaml_name
fi

# Dump a bucket map
bucket_map_file="/tmp/${STACKNAME}-bucket-map.yaml"
cat << EOL > $bucket_map_file
MAP:
  pub: public
  res: restricted
PUBLIC_BUCKETS:
  public: "Public, no EDL"
EOL
aws $AWSENV s3 cp $bucket_map_file s3://${config_bucket}/bucket_map.yaml

# Upload some test files:
echo "this is a public file" | aws $AWSENV s3 cp - s3://$public_bucket/test.txt
echo "this is a restricted file" | aws $AWSENV s3 cp - s3://$restricted_bucket/test.txt

# Get networking parameters
export VPCID=$(aws $AWSENV ec2 describe-vpcs --query "Vpcs[*].VpcId" \
                                             --filters "Name=tag:Name,Values=Application VPC" \
                                             --output text)
export SUBNETID=$(aws $AWSENV ec2 describe-subnets --query "Subnets[?VpcId=='$VPCID'].{ID:SubnetId}[0]" \
                                                   --filters "Name=tag:Name,Values=Private*" \
                                                   --output=text)
export SECURITYGROUP=$(aws $AWSENV ec2 describe-security-groups --query "SecurityGroups[?VpcId=='$VPCID'].{ID:GroupId}" \
                                                                --filters "Name=tag:Name,Values=Application Default*" \
                                                                --output=text)
echo ">> 🎉 PrivateVPC=$VPCID; VPCSecurityGroupIDs=$SECURITYGROUP; VPCSubnetIDs=$SUBNETID;"

# Check that we have a VPC Endpoint
endpoint=$(aws $AWSENV ec2 describe-vpc-endpoints \
                            --query "VpcEndpoints[?(VpcId=='$VPCID' && \
                                    ServiceName=='com.amazonaws.${AWSREGION}.execute-api')].{ID:VpcEndpointId}" \
                            --output=text)
if [ -z $endpoint ]; then
   echo '>> 🤮 ERROR!!!!! There is no VPC Endpoint!'
   exit 1
fi

### Deploy the Stack!
echo ">> Deploying CloudFormation Stack"
edl_authbase="https://$EDL.earthdata.nasa.gov"

aws cloudformation deploy $AWSENV \
  --stack-name ${STACKNAME} \
  --template-file /tmp/$cf_yaml_name \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
        AuthBaseUrl=$edl_authbase \
        BucketMapFile="bucket_map.yaml" \
        BucketnamePrefix="${STACKNAME}-" \
        ConfigBucket=$config_bucket \
        EnableApiGatewayLogToCloudWatch="False" \
        JwtAlgo="RS256" \
        JwtKeySecretName=$jwt_secret_name \
        LambdaCodeDependencyArchive=$layer_zip \
        LambdaCodeS3Bucket=$code_bucket \
        LambdaCodeS3Key=$code_zip \
        LambdaTimeout=6 \
        Loglevel=INFO \
        Maturity=$MAT \
        PermissionsBoundaryName=NGAPShRoleBoundary \
        PrivateVPC=$VPCID \
        SessionTTL=168 \
        StageName=API \
        URSAuthCredsSecretName=$urs_secret_name \
        UseReverseBucketMap="False" \
        VPCSecurityGroupIDs=$SECURITYGROUP \
        VPCSubnetIDs=$SUBNETID

### Validate the deployment

# Validate the Deployment
api_endpoint=$(aws $AWSENV cloudformation describe-stacks \
                           --stack-name=$STACKNAME \
                           --query 'Stacks[0].Outputs[?OutputKey==`ApiEndpoint`].OutputValue' \
                           --output=text)

if [ $api_endpoint == "None" ]; then 
   echo ">> 🤮 CloudFormation stack did not properly deploy"
   exit 0
fi

echo ">> 🎉 API Endpoint is $api_endpoint"
api_endpoint=${api_endpoint%/}

if [[ -z "$BASTIONNAME" || -z "$KEYFILE" ]]; then 
   echo ">> Skipping TEA Validation because of missing --key-file or --bastion"
   exit 0
fi

# Look up Bastion instance id & Start tunnel
echo ">> Finding EC2 Instance id for bastion \"$BASTIONNAME\""
ssm_bastion=$(aws $AWSENV ec2 describe-instances --filters "Name=tag:Name,Values=$BASTIONNAME" \
                                                 --query "Reservations[].Instances[].InstanceId" \
                                                 --output=text)
echo ">> Attempting to connect to bastion $ssm_bastion"

# Brute force retry until it works....
sshrc=255
ssh_loop_count=0

while [[ $sshrc -gt 0 && $ssh_loop_count -lt 4 ]]; do 
    ssh -o ProxyCommand="sh -c 'aws $AWSENV ssm start-session \
                                    --target %h --document-name AWS-StartSSHSession \
                                    --parameters portNumber=22'" \
        -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
        -i $KEYFILE -q -fN -D 127.0.0.1:8001 ec2-user@$ssm_bastion

    sshrc=$? 
    if [[ $sshrc -gt 0 ]]; then
       echo ">> 🤮 COULD NOT ESTABLISH SSH TUNNEL, Trying again..."
       ssh_loop_count=$(($ssh_loop_count + 1))
    fi
done

if [[ $sshrc -gt 0 ]]; then 
   echo '>> 🤮 COULD NOT ESTABLISH SSH TUNNEL AFTER 5 ATTEMPTS!'
   exit 1 
fi

ssh_tunnel_pid=$(pgrep -f 'ssh -o ProxyCommand')

# Attempt to hit /version endpoint
tea_version=$(curl -s --proxy socks5h://localhost:8001 ${api_endpoint}/version)
echo ">> 🎉 TEA/version response was $tea_version"

# Attempt to  download restricted file
http_resp=$(curl --proxy socks5h://localhost:8001 -s \
                 -o /tmp/pub_test.txt -w "%{http_code}" \
                 -L ${api_endpoint}/pub/test.txt)
if [[ $http_resp -eq "200" ]]; then
   echo ">> 🎉 Succesfully fetched public file:"
else
   echo ">> 🤮 There was a problem fetching public file:"
fi
cat /tmp/pub_test.txt

# Generating and EDL App Client Token
echo ">> Generating an EDL App Client token"
edl_resp=$(curl --request POST -s --url "$edl_authbase/oauth/token?grant_type=client_credentials" \
                --header "authorization: Basic $UrsAuth" | jq -r .access_token)

# Check to see we can download a public file
echo ">> Checking to see if $api_endpoint/login is a valid EDL App redirect_uri"
edl_redirect_check=$(curl -s --request GET --header "Authorization: Bearer $edl_resp" \
                             --url $edl_authbase/api/apps/$EDLUID/redirect_uri | \
                     jq -r '.[]' | grep -q "$api_endpoint/login" )

if [[ $? -gt 0 ]]; then
    echo ">> Redirect URI has not yet been added to EDL App"
    post_resp=$( curl -s --request POST --header "Authorization: Bearer $edl_resp" \
                         --data "uri=$api_endpoint/login" \
                         --url $edl_authbase/api/apps/$EDLUID/redirect_uri )
    echo $post_resp | grep -q 'Redirect URI added successfully' 
 
    if [[ $? -gt 0 ]]; then
       echo ">> 🤮 There was a problem adding redirect URI: $post_resp"
    else 
       echo ">> 🎉 URI successfully added to EDL App"
    fi
else
    echo ">> 🎉 Found $api_endpoint/login redirect_uri in EDL App"
fi

# Check to see we get redirected to EDL for authed downloads
echo ">> Ensuring restricted download is redirect to EDL"
http_resp=$(curl --proxy socks5h://localhost:8001 -s \
                 -o /tmp/res_test.txt -w "%{http_code}" \
                 ${api_endpoint}/res/test.txt)
if [[ $http_resp -eq "302" ]]; then
   echo ">> 🎉 Redirect check has passed"
else
   echo ">> 🤮 There was a problem validating auth challenge for restricted data:"
   cat /tmp/res_test.txt
   exit 1
fi 

if [[ -z "$EDLUSER" ]]; then
    echo ">> No EDL User creds provided. Cannot validate download."
    echo ">> Try supplying --edl-user-creds='<EDL-USER>:<EDL-PASS>'"
else
    echo ">> Generating Session cookie"
    cookie_file="/tmp/$STACKNAME.cookiejar"
    rm -rf $cookie_file
    
    # First step, log in 
    auth_dl_url="$edl_authbase/oauth/authorize?client_id=$CLIENTID&redirect_uri=$api_endpoint/login&response_type=code"
    echo ">> Login link is $auth_dl_url"
    login_check=$(curl --proxy socks5h://localhost:8001 -u "$EDLUSER" \
                       -c $cookie_file -b $cookie_file \
                       -L -s -o /tmp/login_test.txt  \
                       -w "%{http_code}" $auth_dl_url)
                                 
    if [[ $login_check -eq "200" ]]; then 
       echo ">> 🎉 Successfully negotiated login... Attempting download"
       echo ">> Attempting to download authenticated file $api_endpoint/res/test.txt"
       
       download_check=$(curl --proxy socks5h://localhost:8001 \
                             -c $cookie_file -b $cookie_file \
                             -L -s -o /tmp/res_test.txt \
                             -w "%{http_code}" $api_endpoint/res/test.txt )
       
       if [[ $download_check -eq "200" ]]; then
          echo ">> 🎉 Successfully fetched restricted file:"
       else
          echo ">> 🤮 There was a problem fetching restricted file:"
       fi
       cat /tmp/res_test.txt
    else
       echo ">> 🤮 Could not complete login:"
       cat /tmp/login_test.txt
    fi 
fi

# Kill the proxy
echo ">> Killing ssh tunnel $ssh_tunnel_pid"
kill -9 $ssh_tunnel_pid
