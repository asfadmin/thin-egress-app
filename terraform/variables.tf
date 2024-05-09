variable "auth_base_url" {
  type        = string
  default     = null
  description = "Is the 'AUTH_BASE_URL' env var in the lambda."
}

variable "bucket_map_file" {
  type        = string
  default     = null
  description = "Path and file of bucketmap file's location in the ConfigBucket."
}

variable "bucketname_prefix" {
  type        = string
  description = "All data buckets should have names prefixed with this. Must be compatible with S3 naming conventions (lower case only, etc)."
}

variable "config_bucket" {
  type        = string
  description = "This is the bucket where config files can be found."
}

variable "cookie_domain" {
  type        = string
  default     = null
  description = "Valid domain for cookie."
}

variable "domain_cert_arn" {
  type        = string
  default     = null
  description = "Certificate Manager SSL Cert ARN if deployed outside NGAP/CloudFront"
}

variable "domain_name" {
  type        = string
  default     = null
  description = "Custom domain name used by redirect_url"
}

variable "download_role_arn" {
  type        = string
  default     = null
  description = "ARN for reading of data buckets."
}

variable "download_role_in_region_arn" {
  type        = string
  default     = null
  description = "ARN for reading of data buckets for in-region requests."
}

variable "html_template_dir" {
  type        = string
  default     = null
  description = "Directory in ConfigBucket where the lambda will look for html templates. Lambda will not look into subdirectories. Please put only html templates in this dir. Leave this field blank to use default templates that are included with the lambda code zip file."
}

variable "jwt_algo" {
  type        = string
  default     = "RS256"
  description = "Algorithm with which to encode the JWT cookie."
}

variable "jwt_secret_name" {
  type        = string
  default     = "jwt_secret_for_tea"
  description = "Name of AWS secret where keys for JWT encode/decode are stored."
}

variable "lambda_code_dependency_archive_key" {
  type        = string
  default     = null
  description = "S3 Key of packaged python modules for lambda dependency layer."
}

variable "lambda_code_s3_bucket" {
  type        = string
  default     = null
  description = "S3 bucket of packaged lambda egress code"
}

variable "lambda_code_s3_key" {
  type        = string
  default     = null
  description = "S3 Key of packaged lambda egress code."
}

variable "lambda_timeout" {
  type        = number
  default     = 6
  description = "Timeout in seconds for lambda."
}

variable "lambda_memory" {
  type        = number
  default     = 1792
  description = "The amount of memory available to the function during execution. Must be multiple of 64. Minimum: 128. Max: 3008"
}

variable "log_api_gateway_to_cloudwatch" {
  type        = bool
  default     = false
  description = "Switch that will enable logging of api gateway request/response to cloudwatch."
}

variable "s3credentials_endpoint" {
  type        = bool
  default     = false
  description = "Switch that will enable deployment of the /s3credentials endpoint for s3 direct access."
}

variable "suppress_head_check" {
  type        = bool
  default     = false
  description = "Do not validate if a file exists before creating pre-signed URL."
}

variable "log_level" {
  type        = string
  default     = null
  description = "Python loglevel."
}

variable "log_type" {
  type        = string
  default     = null
  description = "Type of log entry."
}

variable "maturity" {
  type        = string
  default     = null
  description = "Maturity of deployment."
}

variable "permissions_boundary_name" {
  type        = string
  default     = null
  description = "Optional PermissionsBoundary Policy name. In NGAP2, the policy name is \"NGAPShRoleBoundary\"."
}

variable "private_vpc" {
  type        = string
  default     = null
  description = "Optional internal VPC."
}

variable "session_ttl" {
  type        = number
  default     = null
  description = "Time to live for auth session, in hours. 168 is a week."
}

variable "stack_name" {
  type        = string
  description = "The name of the CloudFormation stack"
}

variable "stage_name" {
  type        = string
  default     = null
  description = "This value will show up as the 'base' of the url path as so: https://xxxxxxxx.execute-api.us-east-1.amazonaws.com/<StageName>/and/so/on."
}

variable "tags" {
  description = "Tags to be applied to managed resources"
  type        = map(string)
  default     = {}
}

variable "urs_auth_creds_secret_name" {
  type        = string
  default     = "urs_creds_for_tea"
  description = "AWS Secrets Manager name of URS creds. Must consist of two rows, names 'UrsId' and 'UrsAuth'."
}

variable "use_reverse_bucket_map" {
  type        = bool
  default     = false
  description = "Standard bucketmaps are not reverse."
}

variable "vpc_security_group_ids" {
  type        = list(string)
  default     = []
  description = "Optional list of security groups for the Lambda function."
}

variable "vpc_subnet_ids" {
  type        = list(string)
  default     = []
  description = "Optional list of Subnets for the Lambda function."
}

variable "use_cors" {
  type        = bool
  default     = false
  description = "Enable cross origin resource sharing"
}
