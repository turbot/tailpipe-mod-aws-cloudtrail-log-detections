dashboard "aws_iam_root_console_login_failed" {

  tags = {
    mitre_attack_ids = "TA0006:T1110"
    service          = "AWS/IAM"
    severity         = "High"
  }

  title = "AWS IAM Root Console Login Failed"

  container {
    table {
      query = query.aws_iam_root_console_login_failed

      column "additional_event_data" {
        wrap = "all"
      }

      column "login_data" {
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

      column "service_event_details" {
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

query "aws_iam_root_console_login_failed" {
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
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and (user_identity ->> 'type') = 'Root'
      and (response_elements::JSON ->> 'ConsoleLogin') = 'Failure'
    order by
      event_time desc;
  EOQ
}
