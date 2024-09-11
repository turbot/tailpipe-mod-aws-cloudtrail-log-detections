dashboard "aws_elb_insecure_access" {

  tags = {
    service = "AWS/ELB"
  }

  title         = "ELB Access Logs - Insecure Access"
  #documentation = file("./dashboards/iam/docs/iam_user_report_mfa.md")

   container {
    table {
      query = query.aws_elb_insecure_access
    }
  }
}

query "aws_elb_insecure_access" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      conn_trace_id as actor_id, -- TODO: What to use here?
      tp_source_ip as source_ip_address,
      request as operation,
      --split_part(request, ' ', 1) as operation,
      array_value(elb)::JSON as resources,
      '123456789012' as index, -- TODO: Use tp_index when available
      'us-east-1' as location, -- TODO: Use tp_location when available
      tp_id as tp_log_id,
      -- Additional dimensions
      elb_status_code,
      target_status_code,
      user_agent,
    from
      aws_elb_access_log
    where
      type = 'https'
      and (ssl_cipher= '-' or ssl_protocol = '-')
    order by
      timestamp desc
  EOQ
}
