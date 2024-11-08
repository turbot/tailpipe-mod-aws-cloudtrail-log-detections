dashboard "aws_iam_user_login_profile_updated" {

  tags = {
    service          = "AWS/IAM"
    mitre_attack_ids = "TA0003:T1098"
  }

  title = "AWS IAM User Login Profile Modified"

  container {
    table {
      query = query.aws_iam_user_login_profile_updated

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


query "aws_iam_user_login_profile_updated" {
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
      and event_name = 'UpdateLoginProfile'
      and (SUBSTR(user_identity ->> 'arn', -LENGTH(request_parameters::json ->> 'userName') - 1) = '/' || request_parameters:: ->> 'userName')
    order by
      event_time desc;
  EOQ
}
