locals {
  vpc_security_group_ids_set = length(var.vpc_security_group_ids) > 0
  cloudformation_template_filename = "${path.module}/thin-egress-app.yaml"
  lambda_source_filename     = "${path.module}/lambda.zip"
  dependency_layer_filename  ="${path.module}/dependencylayer.zip"
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

  tags = var.tags
}

resource "aws_s3_bucket" "lambda_source" {
  tags = var.tags
}

resource "aws_s3_bucket_object" "lambda_source" {
  bucket = aws_s3_bucket.lambda_source.bucket
  key    = "${filemd5(local.lambda_source_filename)}.zip"
  source = local.lambda_source_filename
  etag   = filemd5(local.lambda_source_filename)
}

resource "aws_s3_bucket_object" "lambda_code_dependency_archive" {
  bucket = aws_s3_bucket.lambda_source.bucket
  key    = "${filemd5(local.dependency_layer_filename)}.zip"
  source = local.dependency_layer_filename
  etag   = filemd5(local.dependency_layer_filename)
}

resource "aws_s3_bucket_object" "cloudformation_template" {
  bucket = aws_s3_bucket.lambda_source.bucket
  key    = "${filemd5(local.cloudformation_template_filename)}.yaml"
  source = local.cloudformation_template_filename
  etag   = filemd5(local.cloudformation_template_filename)
}

resource "aws_cloudformation_stack" "thin_egress_app" {
  depends_on   = [
    aws_s3_bucket_object.lambda_source,
    aws_s3_bucket_object.lambda_code_dependency_archive,
    aws_s3_bucket_object.cloudformation_template
  ]
  name         = var.stack_name
  template_url = "https://s3.amazonaws.com/${aws_s3_bucket_object.lambda_source.bucket}/${aws_s3_bucket_object.cloudformation_template.key}"
  capabilities = ["CAPABILITY_NAMED_IAM"]
  parameters = {
    AuthBaseUrl                     = var.auth_base_url
    BucketMapFile                   = var.bucket_map_file
    BucketnamePrefix                = var.bucketname_prefix
    ConfigBucket                    = var.config_bucket
    CookieDomain                    = var.cookie_domain
    DomainCertArn                   = var.domain_cert_arn
    DomainName                      = var.domain_name
    DownloadRoleArn                 = var.download_role_arn
    DownloadRoleInRegionArn         = var.download_role_in_region_arn
    EnableApiGatewayLogToCloudWatch = var.log_api_gateway_to_cloudwatch ? "True" : "False"
    HtmlTemplateDir                 = var.html_template_dir
    JwtAlgo                         = var.jwt_algo
    JwtKeySecretName                = var.jwt_secret_name
    LambdaCodeDependencyArchive     = aws_s3_bucket_object.lambda_code_dependency_archive.key
    LambdaCodeS3Bucket              = aws_s3_bucket_object.lambda_source.bucket
    LambdaCodeS3Key                 = aws_s3_bucket_object.lambda_source.key
    LambdaTimeout                   = var.lambda_timeout
    Loglevel                        = var.log_level
    Maturity                        = var.maturity
    PermissionsBoundaryName         = var.permissions_boundary_name
    PrivateBucketsFile              = var.private_buckets_file
    PrivateVPC                      = var.private_vpc
    PublicBucketsFile               = var.public_buckets_file
    SessionTTL                      = var.session_ttl
    StageName                       = var.stage_name
    SuppressHeadCheck               = var.suppress_head_check ? "True" : "False"
    URSAuthCredsSecretName          = var.urs_auth_creds_secret_name
    UseReverseBucketMap             = var.use_reverse_bucket_map ? "True" : "False"
    VPCSecurityGroupIDs             = local.vpc_security_group_ids_set ? join(",", var.vpc_security_group_ids) : aws_security_group.egress_lambda[0].id
    VPCSubnetIDs                    = join(",", var.vpc_subnet_ids)
  }
  tags = var.tags
}

data "aws_cloudformation_stack" "thin_egress_stack" {
  name = aws_cloudformation_stack.thin_egress_app.name
  depends_on = [
    aws_cloudformation_stack.thin_egress_app
  ]
}
