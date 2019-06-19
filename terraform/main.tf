locals {
  vpc_security_group_ids_set = length(var.vpc_security_group_ids) > 0
}

resource "aws_security_group" "egress_lambda" {
  count  = local.vpc_security_group_ids_set ? 0 : 1
  vpc_id = var.private_vpc
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_cloudformation_stack" "thin_egress_app" {
  name         = var.stack_name
  template_url = var.template_url
  capabilities = ["CAPABILITY_NAMED_IAM"]
  parameters = {
    AuthBaseUrl             = var.auth_base_url
    BucketMapFile           = var.bucket_map_file
    BucketnamePrefix        = var.bucketname_prefix
    ConfigBucket            = var.config_bucket
    DomainName              = var.domain_name
    DownloadRoleArn         = var.download_role_arn
    HtmlTemplateDir         = var.html_template_dir
    LambdaCodeS3Bucket      = var.lambda_code_s3_bucket
    LambdaCodeS3Key         = var.lambda_code_s3_key
    Loglevel                = var.log_level
    Maturity                = var.maturity
    PermissionsBoundaryName = var.permissions_boundary_name
    PrivateBucketsFile      = var.private_buckets_file
    PrivateVPC              = var.private_vpc
    PublicBucketsFile       = var.public_buckets_file
    SessionStore            = var.session_store
    SessionTTL              = var.session_ttl
    StageName               = var.stage_name
    URSAuthCredsSecretName  = var.urs_auth_creds_secret_name
    UseReverseBucketMap     = var.use_reverse_bucket_map ? "True" : "False"
    VPCSecurityGroupIDs     = local.vpc_security_group_ids_set ? join(",", var.vpc_security_group_ids) : aws_security_group.egress_lambda[0].id
    VPCSubnetIDs            = join(",", var.vpc_subnet_ids)
  }
}
