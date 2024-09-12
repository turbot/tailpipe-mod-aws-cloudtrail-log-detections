// TODO: Check query logic
dashboard "aws_iam_access_key_created" {

  tags = {
    service          = "AWS/IAM"
    severity         = "Medium"
    mitre_attack_ids = "TA0003:T1098,TA0005:T1108,TA0005:T1550,TA0008:T1550"
  }

  title = "AWS IAM Access Key Created"

  container {
    table {
      query = query.aws_iam_access_key_created

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
query "aws_iam_access_key_created" {
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
      and event_name = 'CreateAccessKey'
      and (user_identity ->> 'arn') like '%' || (response_elements::json -> 'accessKey' ->> 'userName')
      and error_code is not null
    order by
      event_time desc;
  EOQ
}
