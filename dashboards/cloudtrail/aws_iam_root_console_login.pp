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
      epoch_ms(tp_timestamp) as timestamp,
      user_identity.arn as actor_id,
      tp_source_ip as source_ip_address,
      string_split(event_source, '.')[1] || ':' || event_name as operation,
      tp_connection::varchar as index, -- TODO: Change to tp_index with newer data without varchar cast
      aws_region as location,
      tp_id as tp_log_id,
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
