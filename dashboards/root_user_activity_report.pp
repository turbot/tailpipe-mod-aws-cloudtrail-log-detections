dashboard "root_user_activity_report" {

  title         = "CloudTrail Log Root User Activity Report"
  documentation = file("./dashboards/docs/root_user_activity_report.md")

  tags = {
    type    = "Report"
    service = "AWS/CloudTrail"
  }

  container {
    input "read_only" {
      title = "Include read-only events:"
      width = 2

      option "true" {
        label = "Yes"
      }

      option "false" {
        label = "No"
      }
    }

    input "aws_accounts" {
      title = "Select accounts:"
      query = query.root_user_activity_report_aws_accounts_input
      type  = "multiselect"
      width = 2
    }
  }

  container {
    card {
      query = query.root_user_activity_report_total_logs
      width = 2
      args = [
        self.input.read_only.value,
        self.input.aws_accounts.value
      ]
    }
  }

  container {
    table {
      title = "Note: This table shows a maximum of 10,000 rows"
      query = query.root_user_activity_report_table
      args = [
        self.input.read_only.value,
        self.input.aws_accounts.value
      ]
    }
  }

}

query "root_user_activity_report_total_logs" {
  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      aws_cloudtrail_log
    where
      ($1 = 'true' or ($1 = 'false' and read_only = false))
      and recipient_account_id in $2
      and user_identity.type = 'Root'
  EOQ
}

query "root_user_activity_report_table" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      string_split(event_source, '.')[1] || ':' || event_name as operation,
      user_identity.arn as actor,
      tp_source_ip as source_ip,
      tp_index::varchar as account_id,
      aws_region as region,
      tp_id as source_id,
      *
    from
      aws_cloudtrail_log
    where
      ($1 = 'true' or ($1 = 'false' and read_only = false))
      and recipient_account_id in $2
      and user_identity.type = 'Root'
    order by
      timestamp desc
    limit 10000;
  EOQ
}

# Input queries

query "root_user_activity_report_aws_accounts_input" {
  title = "Root User Activity Report AWS Accounts Input"

  sql = <<-EOQ
    with aws_account_ids as (
      select
        distinct(recipient_account_id) as aws_account_id
      from
      aws_cloudtrail_log
    )
    select
      aws_account_id as label,
      aws_account_id as value
    from
      aws_account_ids
    order by
      aws_account_id;
  EOQ

  tags = {
    folder = "Internal"
  }
}
