dashboard "aws_iam_group_role_user_compromised_key_quarantine_policy_attached" {

  tags = {
    service          = "AWS/IAM"
    severity         = "High"
    mitre_attack_ids = "TA0001:T1078.004,TA0006:T1552.001"
  }

  title = "AWS IAM Group/User/Role Compromised Key Quarantine Policy Attached"

  container {
    table {
      query = query.aws_iam_group_role_user_compromised_key_quarantine_policy_attached

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
query "aws_iam_group_role_user_compromised_key_quarantine_policy_attached" {
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
      event_source = 'iam.amazonaws.com'
      and event_name in ('AttachUserPolicy', 'AttachGroupPolicy', 'AttachRolePolicy')
      and (request_parameters::json ->> 'policyArn') = 'arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2'
    order by
      event_time desc;
  EOQ
}
