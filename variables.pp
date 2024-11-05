variable "database" {
  type        = connection.duckdb
  description = "DuckDB database connection string."
  default     = connection.duckdb.default
}

variable "assume_role_blocklist" {
  type        = list(string)
  default     = ["arn:aws:iam::123456789012:role/FullAdminRole"]
  description = "A list of role ARNs that should not be assumed by users in normal operations."
}
