dashboard "cloudtrail_log_search_by_principal_id" {

  title         = "CloudTrail Logs Search by Principal ID"
  #documentation = file("./dashboards/ec2/docs/ec2_instance_detail.md")

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Report"
  })

  container {

    input "principal_id" {
      title = "Enter a principal ID:"
      type  = "text"
      width = 4
    }

    table {
      query = query.cloudtrail_log_search_by_principal_id
      args  = [self.input.principal_id.value]
    }
  }

}


query "cloudtrail_log_search_by_principal_id" {
  sql = <<-EOQ
    select
      epoch_ms(event_time) as event_time,
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
      user_identity.principal_id = $1
      and not read_only
    order by
      event_time desc;
  EOQ
}
