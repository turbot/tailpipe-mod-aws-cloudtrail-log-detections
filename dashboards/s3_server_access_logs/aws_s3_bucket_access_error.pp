dashboard "aws_s3_bucket_access_error" {

  tags = {
    mitre_attack_ids = "TA0007:T1619"
    service          = "AWS/S3"
    severity         = "low"
  }

  title         = "S3 Server Access Logs - Bucket Access Error"
  #documentation = file("./dashboards/iam/docs/iam_user_report_mfa.md")

   container {
    table {
      query = query.aws_s3_bucket_access_error
    }
  }
}

locals {
  # Store the replace logic in a local variable
  aws_s3_bucket_access_error_sql = local.common_dimensions_s3_log_sql
}

query "aws_s3_bucket_access_error" {
  sql = <<-EOQ
    select
      ${local.aws_s3_bucket_access_error_sql}
      -- Additional dimensions
      http_status,
      error_code,
      user_agent
    from
      aws_s3_server_access_log
    where
      operation ilike 'REST.%.OBJECT'
      and not starts_with(user_agent, 'aws-internal')
      and http_status in (403, 405)
    order by
      timestamp desc
  EOQ
}
