dashboard "aws_iam_access_key_compromised" {

  tags = {
    service          = "AWS/IAM"
    mitre_attack_ids = "TA0006:T1552"
  }

  title = "AWS IAM Access Key Compromised"

  container {
    table {
      query = query.aws_iam_access_key_compromised

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


query "aws_iam_access_key_compromised" {
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
      event_name = 'PutUserPolicy'
      and (request_parameters::json ->> 'policyName') = 'AWSExposedCredentialPolicy_DO_NOT_REMOVE'
      -- TODO: check if we can get more information on the user/ update the where clause to check if AWS added the policy
    order by
      event_time desc;
  EOQ
}
