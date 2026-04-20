module "thin_egress_app" {
  source = "../dist/terraform"

  stack_name = var.stack_name

  auth_base_url                 = var.auth_base_url
  bucket_map_file               = var.bucket_map_file
  bucketname_prefix             = var.bucketname_prefix
  config_bucket                 = var.config_bucket
  log_api_gateway_to_cloudwatch = false
  s3credentials_endpoint        = true
  jwt_algo                      = "RS256"
  jwt_secret_name               = var.jwt_secret_name
  lambda_memory                 = "128"
  lambda_timeout                = "20"
  log_level                     = "DEBUG"
  log_type                      = "json"
  maturity                      = "TEST"
  stage_name                    = "API"
  urs_auth_creds_secret_name    = var.urs_auth_creds_secret_name
  use_cors                      = true
  use_reverse_bucket_map        = false
}
