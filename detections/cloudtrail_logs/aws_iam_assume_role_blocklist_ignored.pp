dashboard "aws_iam_assume_role_blocklist_ignored" {

  tags = {
    service          = "AWS/IAM"
    severity         = "High"
    mitre_attack_ids = "TA0004:T1548"
  }

  title = "AWS IAM Assume Role Blocklist Ignored"

  container {
    table {
      query = query.aws_iam_assume_role_blocklist_ignored

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


query "aws_iam_assume_role_blocklist_ignored" {
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
      event_name = 'AssumeRole'
      and (user_identity ->> 'type') in ('IAMUser', 'FederatedUser')
      and POSITION((request_parameters::json ->> 'roleArn') IN ($1)) = 1 -- 0 means the roleArn is not found
    order by
      event_time desc;
  EOQ

  param "assume_role_blocklist" {
    description = "A string containing role ARNs separated by commas."
    default     = join(",", var.assume_role_blocklist)  # Joins the list into a single string
  }
}
