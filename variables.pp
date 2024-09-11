// Benchmarks and controls for specific services should override the "service" tag
locals {
  aws_common_tags = {
    category = "Security"
    plugin   = "aws"
    service  = "AWS"
  }
}

variable "assume_role_blocklist" {
  type        = list(string)
  default     = ["arn:aws:iam::123456789012:role/FullAdminRole"]
  description = "A list of role ARNs that should not be assumed by users in normal operations."
}
