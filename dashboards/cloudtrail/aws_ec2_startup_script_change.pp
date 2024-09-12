dashboard "aws_ec2_startup_script_change" {

  tags = {
    service          = "AWS/EC2"
    severity         = "High"
    mitre_attack_ids = "TA0002:T1059"
  }

  title = "AWS EC2 Startup Script Change"

  container {
    table {
      query = query.aws_ec2_startup_script_change

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


query "aws_ec2_startup_script_change" {
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
      event_name = 'ModifyInstanceAttribute'
      -- TODO: what other checks can be added
    order by
      event_time desc;
  EOQ
}
