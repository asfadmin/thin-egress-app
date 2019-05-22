## Prepare  

### Create a shortcut so we don't have to keep passing it in. Adjust as necessary. You could just set a DEFAULT awscli config.
```
export AWSENV='--profile=cumulus --region=us-east-1'
```

### Create a bucket map file.

Prefix is `sirc-ingest-dev-`, so  `public` maps to `sirc-ingest-dev-public`.

Data in s3://sirc-ingest-dev-public will be addressable at https://endpoint/SIRC/BROWSE/{object}


```
echo '
MAP: 
   SIRC:
      BROWSE:   public
      SLC:      protected
      GRD:      protected
      METADATA: protected

PUBLIC_BUCKETS:
   -  public' > /tmp/public_bucket.yaml 
```

### Upload bucketmap to internal bucket.
```
aws s3 $AWSENV cp /tmp/public_bucket.yaml s3://sirc-ingest-dev-internal/bucket_map.yaml
```

### Create URS Credentials.
```
aws secretsmanager create-secret $AWSENV \
  --name tea-urs-creds-dev \
  --secret-string '{"UrsId": "VXJzSWQ=","UrsAuth": "VXJzQXV0aA=="}' \
  --description 'URS Credentials for TEA Distribution App'
```

### Gather some environment info necessary to wire up Lambda/API Gateway inside the VPC.
```
export VPCID=$(aws $AWSENV ec2 describe-vpcs --query "Vpcs[*].VpcId" --filters "Name=tag:Name,Values=Application VPC" --output text)
export SUBNETID=$(aws $AWSENV ec2 describe-subnets --query "Subnets[?VpcId=='$VPCID'].{ID:SubnetId}[0]" --filters "Name=tag:Name,Values=Private*" --output=text)
export SECURITYGROUP=$(aws $AWSENV ec2 describe-security-groups --query "SecurityGroups[?VpcId=='$VPCID'].{ID:GroupId}" --filters "Name=tag:Name,Values=Application Default*" --output=text)
```

## Deploy!

### Create the stack stack.  

Unfortunately, the aws cli command `aws cloudformation deploy` doesn't work with template-url, so do it the hard way.

Be sure to change the `<BUILD-ID>` placeholder to the appropriate build: ![Last Release](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastrelease.json), or select one from [ASF's Public Code](https://s3.amazonaws.com/asf.public.code/index.html) bucket. **HINT**: if the `Last Release` is `tea-build.13`, `<BUILD-ID>` below would be `build.13`. 


```
aws cloudformation create-stack $AWSENV \
  --stack-name sirc-tea \
  --template-url https://asf.public.code.s3.amazonaws.com/thin-egress-app/tea-cloudformation-<BUILD-ID>.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter \
       ParameterKey=BucketnamePrefix,ParameterValue=sirc-ingest-dev- \
       ParameterKey=ConfigBucket,ParameterValue=sirc-ingest-dev-internal \
       ParameterKey=PermissionsBoundaryName,ParameterValue=NGAPShNonProdRoleBoundary \
       ParameterKey=URSAuthCredsSecretName,ParameterValue=tea-urs-creds-dev \
       ParameterKey=PrivateVPC,ParameterValue=$VPCID \
       ParameterKey=VPCSecurityGroupIDs,ParameterValue=$SECURITYGROUP \
       ParameterKey=VPCSubnetIDs,ParameterValue=$SUBNETID \
       ParameterKey=StageName,ParameterValue=DEV \
       ParameterKey=HtmlTemplateDir,ParameterValue= 
```

### Wait for completion. 
```
aws cloudformation wait stack-create-complete $AWSENV --stack-name sirc-tea
```

### Get the appropriate REDIRECT_URI for URS.
```
aws cloudformation $AWSENV describe-stacks --stack-name sirc-tea --query "Stacks[0].Outputs[?OutputKey=='URSredirectURI'].{ID:OutputValue}[0]" --output=text
```

### ACTION: Take the value from the above output and add it as redirect_uri in your URS App.

## Validate that the deployment worked!
 
###  Grab the API URL & Bastion DNS Name.
```
export API_URL=$(aws cloudformation $AWSENV describe-stacks --stack-name sirc-tea --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].{ID:OutputValue}[0]" --output=text)
export BASTION=$(aws ec2 $AWSENV describe-instances --filters "Name=tag:Name,Values=NGAP SSH Bastion" --query "Reservations[0].Instances[0].NetworkInterfaces[0].Association.PublicDnsName" --output=text)
```

###  Prove that the app is working!
```
ssh -q ec2-user@$BASTION curl -s -L --HEAD $API_URL/SIRC/BROWSE/SIRC1_11_SLC_ALL_088_040_08_19940414T202148_19940414T202202_browse.png
```


