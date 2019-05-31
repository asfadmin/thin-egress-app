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
   -  public' > tmp/public_bucket.yaml
```

### Upload bucketmap to internal bucket.
```
aws s3 $AWSENV cp /tmp/public_bucket.yaml s3://sirc-ingest-dev-internal/bucket_map.yaml
```

Note that if you make changes to the `bucket_map.yaml` file and re-upload changes are not automatically picked up by the API. You may want to upload a new file and point to that one in your deployment step.

### Create URS Credentials.
```
aws secretsmanager create-secret $AWSENV \
  --name tea-urs-creds-dev \
  --secret-string '{"UrsId": "VXJzSWQ=","UrsAuth": "VXJzQXV0aA=="}' \
  --description 'URS Credentials for TEA Distribution App'
```

`UrsId` is the application client id from URS
`UrsAuth` is the base64 encoding of the application client id and password in this format: `base64("ClientId:Password")`

To generate the `UrsAuth`, run the following command with your client id and password: `echo -n 'client:password' | base64`

### Gather some environment info necessary to wire up Lambda/API Gateway inside the VPC.
```
export VPCID=$(aws $AWSENV ec2 describe-vpcs --query "Vpcs[*].VpcId" --filters "Name=tag:Name,Values=Application VPC" --output text)
export SUBNETID=$(aws $AWSENV ec2 describe-subnets --query "Subnets[?VpcId=='$VPCID'].{ID:SubnetId}[0]" --filters "Name=tag:Name,Values=Private*" --output=text)
export SECURITYGROUP=$(aws $AWSENV ec2 describe-security-groups --query "SecurityGroups[?VpcId=='$VPCID'].{ID:GroupId}" --filters "Name=tag:Name,Values=Application Default*" --output=text)
echo "PrivateVPC=$VPCID; VPCSecurityGroupIDs=$SECURITYGROUP; VPCSubnetIDs=$SUBNETID;"
```

### Grab the latest Cloudformation Template.
```
export CF_TEMPLATE=$(aws $AWSENV s3api list-objects --bucket asf.public.code --prefix thin-egress-app --query "reverse(sort_by(Contents,&LastModified))[?starts_with(Key, 'thin-egress-app/tea-cloudformation-build')] | [0].Key" --output=text)
```

## Deploy!

### Create the stack stack.

Unfortunately, the aws cli command `aws cloudformation deploy` doesn't work with template-url, so do it the hard way.

This will deploy the latest codebase, currently: ![Last Release](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fs3.amazonaws.com%2Fasf.public.code%2Fthin-egress-app%2Flastrelease.json). Alternatively, you can select a Cloudformation template from [ASF's Public Code](https://s3.amazonaws.com/asf.public.code/index.html) bucket.


```
aws cloudformation create-stack $AWSENV \
  --stack-name sirc-tea \
  --template-url https://asf.public.code.s3.amazonaws.com/$CF_TEMPLATE \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter \
       ParameterKey=BucketnamePrefix,ParameterValue=sirc-ingest-dev- \
       ParameterKey=ConfigBucket,ParameterValue=sirc-ingest-dev-internal \
       ParameterKey=PermissionsBoundaryName,ParameterValue=NGAPShNonProdRoleBoundary \
       ParameterKey=BucketMapFile,ParameterValue=bucket_map.yaml \
       ParameterKey=URSAuthCredsSecretName,ParameterValue=tea-urs-creds-dev \
       ParameterKey=PrivateVPC,ParameterValue=$VPCID \
       ParameterKey=VPCSecurityGroupIDs,ParameterValue=$SECURITYGROUP \
       ParameterKey=VPCSubnetIDs,ParameterValue=$SUBNETID \
       ParameterKey=StageName,ParameterValue=DEV \
       ParameterKey=HtmlTemplateDir,ParameterValue=
```

Make sure to replace `BucketNamePrefix`, `ConfigBucket`, and possibly `URSAuthCredsSecretName` and `BucketMapFile` with values specific to your account.

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

## Redeploying

When deploying changes after the initial stack creation, use the following commands:

```
aws cloudformation create-stack $AWSENV \
   ...
```

```
aws cloudformation wait stack-update-complete $AWSENV --stack-name sirc-tea
```

