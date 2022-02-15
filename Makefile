SOURCES := \
	lambda/app.py \
	lambda/tea_bumper.py \
	lambda/update_lambda.py

RESOURCES := $(wildcard lambda/templates/*)
TERRAFORM := $(wildcard terraform/*)

# Output directory
DIR := dist
EMPTY := $(DIR)/empty
# Temporary artifacts
DIST_SOURCES := $(SOURCES:lambda/%=$(DIR)/code/%)
DIST_RESOURCES := $(RESOURCES:lambda/%=$(DIR)/code/%)
DIST_TERRAFORM := $(TERRAFORM:terraform/%=$(DIR)/terraform/%)

BUCKET_MAP_OBJECT_KEY := DEFAULT

DATE := $(shell date -u "+%b %d %Y, %T %Z")
DATE_SHORT := $(shell date -u "+%Y%m%dT%H%M%S")
BUILD_ID := $(shell git rev-parse --short HEAD 2>/dev/null || echo "SNAPSHOT")

DOCKER := docker
# On Linux we need to do a bit of userid finagling so that the output files
# end up being owned by us and not by root. On Mac this works out of the box.
DOCKER_USER_ARG := --user "$(shell id -u):$(shell id -g)"
DOCKER_COMMAND := $(DOCKER) run --rm $(DOCKER_USER_ARG) -v "$$PWD":/var/task lambci/lambda:build-python3.8

#####################
# Deployment Config #
#####################

# A tag to distinguish between artifacts of the same name. The tag should be
# different for each build.
S3_ARTIFACT_TAG = $(DATE_SHORT)


# Include custom configuration
Makefile.config:
	@echo
	@echo "It looks like you are building TEA for the first time."
	@echo "Please review the configuration in '$@' and run Make again."
	@echo
	@cp Makefile.config.example $@
	@exit 1

include Makefile.config


.DEFAULT_GOAL := all
.PHONY: all
all: build ;

##############################
# Local building/development #
##############################

# Build everything
.PHONY: build
build: \
	$(DIR)/thin-egress-app-code.zip \
	$(DIR)/thin-egress-app-dependencies.zip \
	$(DIR)/thin-egress-app.yaml \
	$(DIR)/thin-egress-app-terraform.zip

# Build individual components
.PHONY: dependencies
dependencies: $(DIR)/thin-egress-app-dependencies.zip
	@echo "Built dependency layer for version ${BUILD_ID}"

.PHONY: code
code: $(DIR)/thin-egress-app-code.zip
	@echo "Built code for version ${BUILD_ID}"

.PHONY: yaml
yaml: $(DIR)/thin-egress-app.yaml
	@echo "Built CloudFormation template for version ${BUILD_ID}"

.PHONY: terraform
terraform: $(DIR)/thin-egress-app-terraform.zip
	@echo "Build Terraform zip file for version ${BUILD_ID}"

.PHONY: clean
clean:
	rm -rf $(DIR)

$(DIR)/thin-egress-app-dependencies.zip: requirements.txt
	rm -rf $(DIR)/python
	@mkdir -p $(DIR)/python
	$(DOCKER_COMMAND) build/dependency_builder.sh "$(DIR)/thin-egress-app-dependencies.zip" "$(DIR)"

.SECONDARY: $(DIST_RESOURCES)
$(DIST_RESOURCES): $(DIR)/code/%: lambda/%
	@mkdir -p $(@D)
	cp $< $@

.SECONDARY: $(DIST_SOURCES)
$(DIST_SOURCES): $(DIR)/code/%: lambda/%
	@mkdir -p $(@D)
	cp $< $@
	python3 scripts/sed.py -i $@ "<BUILD_ID>" "${BUILD_ID}"

$(DIR)/thin-egress-app-code.zip: $(DIST_SOURCES) $(DIST_RESOURCES)
	@mkdir -p $(DIR)/code
	cd $(DIR)/code && zip -r ../thin-egress-app-code.zip .

$(DIR)/bucket-map.yaml:
	cp config/bucket-map-template.yaml $@

$(DIR)/thin-egress-app.yaml: cloudformation/thin-egress-app.yaml
	@mkdir -p $(DIR)
	cp cloudformation/thin-egress-app.yaml $(DIR)/thin-egress-app.yaml
ifdef CF_DEFAULT_CODE_BUCKET
	python3 scripts/sed.py -i $(DIR)/thin-egress-app.yaml "asf.public.code" "${CF_DEFAULT_CODE_BUCKET}"
endif
	python3 scripts/sed.py -i $(DIR)/thin-egress-app.yaml "<DEPENDENCY_ARCHIVE_PATH_FILENAME>" "${CF_DEFAULT_DEPENDENCY_ARCHIVE_KEY}"
	python3 scripts/sed.py -i $(DIR)/thin-egress-app.yaml "<CODE_ARCHIVE_PATH_FILENAME>" "${CF_DEFAULT_CODE_ARCHIVE_KEY}"
	python3 scripts/sed.py -i $(DIR)/thin-egress-app.yaml "<BUILD_ID>" "${CF_BUILD_VERSION}"
	python3 scripts/sed.py -i $(DIR)/thin-egress-app.yaml "^Description:.*" 'Description: "${CF_DESCRIPTION}"'

.SECONDARY: $(DIST_TERRAFORM)
$(DIST_TERRAFORM): $(DIR)/%: %
	@mkdir -p $(@D)
	cp $< $@

$(DIR)/thin-egress-app-terraform.zip: \
	$(DIR)/thin-egress-app-code.zip \
	$(DIR)/thin-egress-app-dependencies.zip \
	$(DIR)/thin-egress-app.yaml \
	$(DIST_TERRAFORM)
	@mkdir -p $(DIR)/terraform
	cp $(DIR)/thin-egress-app-code.zip $(DIR)/terraform/lambda.zip
	cp $(DIR)/thin-egress-app-dependencies.zip $(DIR)/terraform/dependencylayer.zip
	cp $(DIR)/thin-egress-app.yaml $(DIR)/terraform/thin-egress-app.yaml
	cd $(DIR)/terraform && zip ../thin-egress-app-terraform.zip \
		*.tf \
		thin-egress-app.yaml \
		lambda.zip \
		dependencylayer.zip

##############
# Deployment #
##############

# Empty targets so we don't re-deploy stuff that is unchanged. Technically they
# might not be empty, but their purpose is the same.
# https://www.gnu.org/software/make/manual/html_node/Empty-Targets.html

$(EMPTY)/.deploy-dependencies: $(DIR)/thin-egress-app-dependencies.zip
	@echo "Deploying dependencies"
	$(AWS) s3 cp --profile=$(AWS_PROFILE) $< \
		s3://$(CODE_BUCKET)/$(CODE_PREFIX)dependencies-$(S3_ARTIFACT_TAG).zip

	@mkdir -p $(EMPTY)
	@echo $(S3_ARTIFACT_TAG) > $(EMPTY)/.deploy-dependencies

$(EMPTY)/.deploy-code: $(DIR)/thin-egress-app-code.zip
	@echo "Deploying code"
	$(AWS) s3 cp --profile=$(AWS_PROFILE) \
		$(DIR)/thin-egress-app-code.zip \
		s3://$(CODE_BUCKET)/$(CODE_PREFIX)code-$(S3_ARTIFACT_TAG).zip

	@mkdir -p $(EMPTY)
	@echo $(S3_ARTIFACT_TAG) > $(EMPTY)/.deploy-code

$(EMPTY)/.deploy-bucket-map: $(DIR)/bucket-map.yaml
	@echo "Deploying bucket map"
	$(AWS) s3 cp --profile=$(AWS_PROFILE) $< \
		s3://$(CONFIG_BUCKET)/$(CONFIG_PREFIX)bucket-map-$(S3_ARTIFACT_TAG).yaml

	@mkdir -p $(EMPTY)
	@echo $(S3_ARTIFACT_TAG) > $(EMPTY)/.deploy-bucket-map

# Optionally upload a bucket map if the user hasn't specified one
BUCKET_MAP_REQUIREMENT :=
ifeq ($(BUCKET_MAP_OBJECT_KEY), DEFAULT)
BUCKET_MAP_REQUIREMENT := $(EMPTY)/.deploy-bucket-map
BUCKET_MAP_OBJECT_KEY = $(CONFIG_PREFIX)bucket-map-`cat $(EMPTY)/.deploy-bucket-map`.yaml
endif

$(EMPTY)/.deploy-stack: $(DIR)/thin-egress-app.yaml $(EMPTY)/.deploy-dependencies $(EMPTY)/.deploy-code $(BUCKET_MAP_REQUIREMENT)
	@echo "Deploying stack '$(STACK_NAME)'"
	$(AWS) cloudformation deploy \
			--profile=$(AWS_PROFILE) \
			--stack-name $(STACK_NAME) \
			--template-file $(DIR)/thin-egress-app.yaml \
			--capabilities CAPABILITY_NAMED_IAM \
			--parameter-overrides \
					LambdaCodeS3Key="$(CODE_PREFIX)code-`cat $(EMPTY)/.deploy-code`.zip" \
					LambdaCodeDependencyArchive="$(CODE_PREFIX)dependencies-`cat $(EMPTY)/.deploy-dependencies`.zip" \
					BucketMapFile="$(BUCKET_MAP_OBJECT_KEY)" \
					URSAuthCredsSecretName=$(URS_CREDS_SECRET_NAME) \
					AuthBaseUrl=$(URS_URL) \
					ConfigBucket=$(CONFIG_BUCKET) \
					LambdaCodeS3Bucket=$(CODE_BUCKET) \
					PermissionsBoundaryName= \
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
					JwtKeySecretName=$(JWT_KEY_SECRET_NAME) \
					UseReverseBucketMap="False" \
					UseCorsCookieDomain="False"

	@mkdir -p $(EMPTY)
	@touch $(EMPTY)/.deploy-stack

# Deploy everything
.PHONY: deploy
deploy: deploy-code deploy-dependencies deploy-stack

# Deploy individual components
.PHONY: deploy-code
deploy-code: $(EMPTY)/.deploy-code

.PHONY: deploy-dependencies
deploy-dependencies: $(EMPTY)/.deploy-dependencies

.PHONY: deploy-bucket-map
deploy-bucket-map: $(EMPTY)/.deploy-bucket-map

.PHONY: deploy-stack
deploy-stack: $(EMPTY)/.deploy-stack

# Remove the empty target files so that aws commands will be run again
.PHONY: cleandeploy
cleandeploy:
	rm -r $(EMPTY)

###############
# Development #
###############

.PHONY: test
test:
	pytest --cov=lambda --cov-report=term-missing --cov-branch tests
