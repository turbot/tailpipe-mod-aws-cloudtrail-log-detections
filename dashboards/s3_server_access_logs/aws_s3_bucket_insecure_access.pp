dashboard "aws_s3_bucket_insecure_access" {

  tags = {
    mitre_attack_ids = "TA0009:T1530"
    service          = "AWS/S3"
    severity         = "low"
  }

  title         = "S3 Server Access Logs - Bucket Insecure Access"
  #documentation = file("./dashboards/iam/docs/iam_user_report_mfa.md")

   container {
    table {
      query = query.aws_s3_bucket_insecure_access
    }
  }
}

locals {
  # Store the replace logic in a local variable
  aws_s3_bucket_insecure_access_sql = local.common_dimensions_s3_log_sql
}

query "aws_s3_bucket_insecure_access" {
  sql = <<-EOQ
    select
      ${local.aws_s3_bucket_insecure_access_sql}
      -- Additional dimensions
      http_status,
      user_agent
    from
      aws_s3_server_access_log
    where
      operation ilike 'REST.%.OBJECT' -- Ignore S3 initiated events
      and (cipher_suite is null or tls_version is null)
    order by
      timestamp desc
  EOQ
}
