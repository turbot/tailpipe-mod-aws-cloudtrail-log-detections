dashboard "cloudtrail_logs_search_by_source_ip" {

  title         = "CloudTrail Logs Search by Source IP"
  #documentation = file("./dashboards/ec2/docs/ec2_instance_detail.md")

  tags = merge(local.cloudtrail_logs_common_tags, {
    type = "Report"
  })

  container {

    input "detection_range" {
      title = "Select the date range:"
      type  = "date_range"
      width = 4
      # TODO: Do we need this sql arg?
      sql   = "select 1;"
    }

  }

  container {

    input "source_ip" {
      title = "Enter a source IP address:"
      type  = "text"
      width = 4
    }

    table {
      query = query.cloudtrail_logs_search_by_source_ip
      args  = [self.input.source_ip.value]
    }
  }

}

query "cloudtrail_logs_search_by_source_ip" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      tp_id,
      event_name,
      user_identity.principal_id as principal_id,
      user_identity.arn as user_arn,
      tp_source_ip as source_ip,
      error_code,
      error_message,
      aws_region as region,
      recipient_account_id as account_id,
      user_identity,
      user_agent,
      request_parameters,
      response_elements,
      additional_event_data,
      resources,
    from
      aws_cloudtrail_log
    where
      tp_source_ip = $1
    order by
      event_time desc;
  EOQ
}
