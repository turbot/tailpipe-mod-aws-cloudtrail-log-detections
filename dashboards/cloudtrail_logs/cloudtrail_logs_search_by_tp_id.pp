dashboard "cloudtrail_logs_search_by_tp_id" {

  title         = "CloudTrail Logs Search by Tailpipe ID"
  #documentation = file("./dashboards/ec2/docs/ec2_instance_detail.md")

  tags = merge(local.cloudtrail_logs_common_tags, {
    type = "Detail"
  })

  container {

    input "tp_id" {
      title = "Enter a Tailpipe ID:"
      type  = "text"
      width = 4
    }

    table {
      query = query.cloudtrail_logs_search_by_tp_id
      args  = [self.input.tp_id.value]
      type  = "line"

      column "user_identity" {
        wrap = "all"
      }

      column "user_agent" {
        wrap = "all"
      }

      column "request_parameters" {
        wrap = "all"
      }

      column "response_elements" {
        wrap = "all"
      }

      column "additional_event_data" {
        wrap = "all"
      }

      column "resources" {
        wrap = "all"
      }

    }
  }

}

query "cloudtrail_logs_search_by_tp_id" {
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
      user_identity::json as user_identity,
      user_agent,
      request_parameters,
      response_elements,
      additional_event_data,
      resources,
    from
      aws_cloudtrail_log
    where
      tp_id = $1;
  EOQ
}
