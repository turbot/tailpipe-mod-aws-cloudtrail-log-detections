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

query "aws_s3_bucket_insecure_access" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      requester as actor_id,
      tp_source_ip as source_ip_address,
      operation,
      bucket || '/' || key as resources,
      '123456789012' as index, -- TODO: Use tp_index when available
      'us-east-1' as location, -- TODO: Use tp_location when available
      tp_id as tp_log_id,
      -- Additional dimensions
      http_status,
      user_agent
    from
      aws_s3_server_access_log
    where
      operation ilike 'REST.%.OBJECT' -- Ignore S3 initiated events
      --operation not ilike 'REST.%.OBJECT' -- Ignore S3 initiated events
      --and (cipher_suite is null or tls_version is null)
    order by
      timestamp desc
  EOQ
}
