# TODO(reweeden): docs
SOURCES = \
	lambda/app.py \
	lambda/tea_bumper.py \
	lambda/update_lambda.py

RESOURCES = \
	lambda/templates

DIST = $(SOURCES:lambda=dist/code)
DIST_RESOURCES = $(RESOURCES:lambda=dist/code)

CODE_BUCKET =
CODE_DIR = tea-dev

AWS_PROFILE = default
AWS_DEFAULT_REGION = us-west-2

JWTALGO = RS256
JWTKEYSECRETNAME = bbarton_rsa_keys_4_jwt
LAMBDA_TIMEOUT = 6
LAMBDA_MEMORY = 128
URS_URL = https://uat.urs.earthdata.nasa.gov
URS_CREDS_SECRET_NAME = URS_creds_ASF_DATA_ACCESS_EGRESS_CONTROL_UAT
BUCKETNAME_PREFIX = rain-uw2-t-

BUILD_ID := $(shell git rev-parse --short HEAD)

.PHONY: build clean default deploy deploy-dependencies deploy-code deploy-cloudformation layer-builder test

default:
	@echo "WIP"
	@echo "BUILD_ID: ${BUILD_ID}"

build: dist/code-$(BUILD_ID).zip dist/dependencies-$(BUILD_ID).zip dist/thin-egress-app-$(BUILD_ID).yaml

clean:
	rm -r dist

dist/thin-egress-app-$(BUILD_ID).yaml: cloudformation/thin-egress-app.yaml
	mkdir -p dist
	cp cloudformation/thin-egress-app.yaml dist/thin-egress-app-$(BUILD_ID).yaml
	sed -i -e "s/asf.public.code/${CODE_BUCKET}/" dist/thin-egress-app-$(BUILD_ID).yaml
	sed -i -e "s/<CODE_ARCHIVE_PATH_FILENAME>/${CODE_DIR}\\/code-${BUILD_ID}.zip/" dist/thin-egress-app-$(BUILD_ID).yaml
	sed -i -e "s/<DEPENDENCY_ARCHIVE_PATH_FILENAME>/${CODE_DIR}\\/dependencies-${BUILD_ID}.zip/" dist/thin-egress-app-$(BUILD_ID).yaml
	sed -i -e "s/<BUILD_ID>/${BUILD_ID}/g" dist/thin-egress-app-$(BUILD_ID).yaml
	sed -i -e "s/^Description:.*/Description: \"TEA snapshot, version: ${BUILD_ID}\"/" dist/thin-egress-app-$(BUILD_ID).yaml

dist/code-$(BUILD_ID).zip: $(DIST) $(DIST_RESOURCES)
	mkdir -p dist/code
	cp -r $(DIST) dist/code
	cp -r $(DIST_RESOURCES) dist/code
	find dist/code -type f -exec sed -i "s/<BUILD_ID>/${BUILD_ID}/g" {} \;
	cd dist/code && zip -r ../code-$(BUILD_ID).zip .

dist/dependencies-$(BUILD_ID).zip: requirements.txt
	mkdir -p dist
	WORKSPACE=`pwd` DEPENDENCYLAYERFILENAME=dist/dependencies-$(BUILD_ID).zip build/dependency_builder.sh

deploy-dependencies: dist/dependencies-$(BUILD_ID).zip
	aws s3 cp --profile=$(AWS_PROFILE) dist/dependencies-$(BUILD_ID).zip s3://$(CODE_BUCKET)/$(CODE_DIR)/dependencies-$(BUILD_ID).zip

deploy-code: dist/code-$(BUILD_ID).zip
	aws s3 cp --profile=$(AWS_PROFILE) dist/code-$(BUILD_ID).zip s3://$(CODE_BUCKET)/$(CODE_DIR)/code-$(BUILD_ID).zip

deploy-cloudformation: dist/thin-egress-app-$(BUILD_ID).yaml
	aws cloudformation deploy --region=$(AWS_DEFAULT_REGION) \
						 --stack-name thin-egress-app-$(BUILD_ID) \
						 --template-file dist/thin-egress-app-$(BUILD_ID).yaml \
						 --capabilities CAPABILITY_NAMED_IAM \
						 --parameter-overrides \
							 URSAuthCredsSecretName=$(URS_CREDS_SECRET_NAME) \
							 AuthBaseUrl=$(URS_URL) \
							 ConfigBucket=$(BUCKETNAME_PREFIX)config \
							 PermissionsBoundaryName= \
							 BucketMapFile=bucket_map_customheaders.yaml \
							 PublicBucketsFile="" \
							 PrivateBucketsFile="" \
							 BucketnamePrefix=$(BUCKETNAME_PREFIX) \
							 DownloadRoleArn="" \
							 DownloadRoleInRegionArn="" \
							 HtmlTemplateDir= \
							 StageName=API \
							 Loglevel=DEBUG \
							 Logtype=json \
							 Maturity=DEV\
							 PrivateVPC= \
							 VPCSecurityGroupIDs= \
							 VPCSubnetIDs= \
							 EnableApiGatewayLogToCloudWatch="False" \
							 DomainName=$(DOMAIN_NAME-"") \
							 DomainCertArn=$(DOMAIN_CERT_ARN-"")  \
							 CookieDomain=$(COOKIE_DOMAIN-"") \
							 LambdaTimeout=$(LAMBDA_TIMEOUT) \
							 LambdaMemory=$(LAMBDA_MEMORY) \
							 JwtAlgo=$(JWTALGO) \
							 JwtKeySecretName=$(JWTKEYSECRETNAME) \
							 UseReverseBucketMap="False" \
							 UseCorsCookieDomain="False"

deploy: deploy-dependencies deploy-code deploy-cloudformation

layer-builder:
	docker build -t layer-builder -f build/dependency_layer_builder.Dockerfile build

test:
	pytest --cov=lambda --cov-report=term-missing --cov-branch tests
