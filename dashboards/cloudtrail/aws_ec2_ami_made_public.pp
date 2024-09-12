dashboard "aws_ec2_ami_made_public" {

  tags = {
    service          = "AWS/EC2"
    severity         = "Medium"
    mitre_attack_ids = "TA0010:T1537"
  }

  title = "AWS EC2 AMI Made Public"

  container {
    table {
      query = query.aws_ec2_ami_made_public

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
query "aws_ec2_ami_made_public" {
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
      event_name = 'ModifyImageAttribute'
      and (request_parameters::json -> 'launchPermission' -> 'add' ->> 'items' ) = '[{ "group": "all" }]'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
