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

variable "jwt_secret_name" {
  type        = string
  default     = "jwt_secret_for_tea"
  description = "Name of AWS secret where keys for JWT encode/decode are stored."
}

variable "urs_auth_creds_secret_name" {
  type        = string
  default     = "urs_creds_for_tea"
  description = "AWS Secrets Manager name of URS creds. Must consist of two rows, names 'UrsId' and 'UrsAuth'."
}

variable "stack_name" {
  type        = string
  description = "The name of the TEA stack"
}
