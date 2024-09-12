dashboard "aws_ebs_encryption_by_default_disabled" {

  tags = {
    service          = "AWS/EBS"
    severity         = "Medium"
    mitre_attack_ids = "TA0040:T1486,TA0040:T1565"
  }

  title = "AWS EBS Encryption By Default Disabled"

  container {
    table {
      query = query.aws_ebs_encryption_by_default_disabled

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
query "aws_ebs_encryption_by_default_disabled" {
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
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DisableEbsEncryptionByDefault'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
