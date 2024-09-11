dashboard "aws_securityhub_finding_evasion" {

  tags = {
    service          = "AWS/SecurityHub"
    // TODO: add severity tags
    mitre_attack_ids = "TA0005:T1562"
  }

  title = "AWS Security Hub Finding Evasion"

  container {
    table {
      query = query.aws_securityhub_finding_evasion

      column "additional_event_data" {
        wrap = "all"
      }

      column "request_parameters" {
        wrap = "all"
      }

      column "response_elements" {
        wrap = "all"
      }

      column "resources" {
        wrap = "all"
      }

      column "user_arn" {
        wrap = "all"
      }

      column "user_agent" {
        wrap = "all"
      }

      column "user_identity" {
        wrap = "all"
      }

    }
  }
}

// TODO: Use normalized timestamp column
query "aws_securityhub_finding_evasion" {
  sql = <<-EOQ
    select
      epoch_ms(event_time) as event_time,
      event_name,
      user_identity.arn as user_arn,
      source_ip_address,
      aws_region,
      recipient_account_id as account_id,
      user_agent,
      additional_event_data,
      request_parameters,
      response_elements,
      service_event_details,
      resources,
      user_identity
    from
      aws_cloudtrail_log
    where
      event_source = 'securityhub.amazonaws.com'
      and event_name in ('BatchUpdateFindings', 'DeleteInsight', 'UpdateFindings', 'UpdateInsight') 
    order by
      event_time desc;
  EOQ
}
