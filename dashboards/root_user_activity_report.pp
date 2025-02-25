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

      option "false" {
        label = "No"
      }

      option "true" {
        label = "Yes"
      }

    }

    input "aws_accounts" {
      title = "Select accounts:"
      query = query.root_user_activity_report_aws_accounts_input
      type  = "multiselect"
      width = 2
    }

    input "event_names" {
      title = "Select event names:"
      query = query.root_user_activity_report_event_names_input
      type  = "multiselect"
      width = 2
    }

    input "source_ip_addresses" {
      title = "Select source IPs:"
      query = query.root_user_activity_report_source_ip_addresses_input
      type  = "multiselect"
      width = 2
    }

    input "event_version" {
      title = "Select event version:"
      query = query.root_user_activity_report_event_version_input
      type  = "select"
      width = 2
    }

  }

  container {
    card {
      query = query.root_user_activity_report_total_logs
      width = 2
      args = [
        self.input.read_only.value,
        self.input.aws_accounts.value,
        self.input.event_names.value,
        self.input.source_ip_addresses.value,
        self.input.event_version.value
      ]
    }
  }

  container {
    table {
      title = "Note: This table shows a maximum of 10,000 rows"
      query = query.root_user_activity_report_table
      args = [
        self.input.read_only.value,
        self.input.aws_accounts.value,
        self.input.event_names.value,
        self.input.source_ip_addresses.value,
        self.input.event_version.value
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
      and ('all' in $2 or (recipient_account_id in $2))
      and ('all' in $3 or (event_name in $3))
      and ('all' in $4 or (source_ip_address in $4))
      and ($5 = 'all' or (event_version in $5))
      --and user_identity.type = 'Root'
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
      and ('all' in $2 or (recipient_account_id in $2))
      and ('all' in $3 or (event_name in $3))
      and ('all' in $4 or (source_ip_address in $4))
      and ($5 = 'all' or (event_version in $5))
      --and user_identity.type = 'Root'
    order by
      timestamp desc
    limit 100;
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
      'All' as label,
      'all' as value
    union all
    select
      aws_account_id as label,
      aws_account_id as value
    from
      aws_account_ids
  EOQ

  tags = {
    folder = "Internal"
  }
}

query "root_user_activity_report_event_names_input" {
  title = "Root User Activity Report Event Names Input"

  sql = <<-EOQ
    with event_names as (
      select
        distinct(event_name) as event_name
      from
        aws_cloudtrail_log
      order by
        event_name
    )
    select
      'All' as label,
      'all' as value
    union all
    select
      event_name as label,
      event_name as value
    from
      event_names
  EOQ

  tags = {
    folder = "Internal"
  }
}

query "root_user_activity_report_source_ip_addresses_input" {
  title = "Root User Activity Report Source IP Addresses Input"

  sql = <<-EOQ
    with source_ip_addresses as (
      select
        distinct(source_ip_address) as source_ip_address
      from
        aws_cloudtrail_log
      order by
        source_ip_address
    )
    select
      'All' as label,
      'all' as value
    union all
    select
      source_ip_address as label,
      source_ip_address as value
    from
      source_ip_addresses
  EOQ

  tags = {
    folder = "Internal"
  }
}

query "root_user_activity_report_event_version_input" {
  title = "Root User Activity Report Event Version Input"

  sql = <<-EOQ
    with event_versions as (
      select
        distinct(event_version) as event_version
      from
        aws_cloudtrail_log
      order by
        event_version
    )
    select
      'All' as label,
      'all' as value
    union all
    select
      event_version as label,
      event_version as value
    from
      event_versions
  EOQ

  tags = {
    folder = "Internal"
  }
}
