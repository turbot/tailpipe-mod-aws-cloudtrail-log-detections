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

query "aws_s3_bucket_access_error" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      requester as actor_id,
      tp_source_ip as source_ip_address,
      operation,
      array_value(bucket || '/' || key)::JSON as resources,
      '123456789012' as index, -- TODO: Use tp_index when available
      'us-east-1' as location, -- TODO: Use tp_location when available
      tp_id as tp_log_id,
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
