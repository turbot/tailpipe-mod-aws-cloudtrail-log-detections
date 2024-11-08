variable "database" {
  type        = connection.tailpipe
  description = "Tailpipe database connection string."
  default     = connection.tailpipe.default
}

variable "assume_role_blocklist" {
  type        = list(string)
  default     = ["arn:aws:iam::123456789012:role/FullAdminRole"]
  description = "A list of role ARNs that should not be assumed by users in normal operations."
}
