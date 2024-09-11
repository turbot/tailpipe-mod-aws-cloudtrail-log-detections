dashboard "aws_iam_root_console_login_detection" {

  tags = {
    mitre_attack_ids = "TA0004:T1078"
    service          = "AWS/IAM"
    severity         = "high"
  }

  title = "CloudTrail Logs - IAM Root Console Login"

  container {
    table {
      query = query.aws_iam_root_console_login_detection

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

query "aws_iam_root_console_login_detection" {
  sql = <<-EOQ
    select
      ${local.common_dimensions_cloudtrail_log_sql}
      -- Additional dimensions
      (additional_event_data::JSON) as login_data,
      --additional_event_data,
      --request_parameters,
      --response_elements,
      --resources,
      --service_event_details,
      user_agent,
      --user_identity
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      --and user_identity.type = 'Root'
      and (response_elements::JSON ->> 'ConsoleLogin') = 'Success'
    order by
      event_time desc;
  EOQ
}
