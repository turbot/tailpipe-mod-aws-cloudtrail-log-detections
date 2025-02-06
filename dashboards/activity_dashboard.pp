dashboard "activity_dashboard" {

  title         = "CloudTrail Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

  tags = {
    type    = "Dashboard"
    service = "AWS/CloudTrail"
  }

  container {

    # Analysis
    card {
      query = query.activity_dashboard_total_logs
      width = 2
    }

  }

  container {

    chart {
      title = "Logs by Account"
      query = query.activity_dashboard_logs_by_account
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Region"
      query = query.activity_dashboard_logs_by_region
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Actors (Excluding AWS Services)"
      query = query.activity_dashboard_logs_by_actor
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Source IPs (Excluding AWS Services and Internal)"
      query = query.activity_dashboard_logs_by_source_ip
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Services (Excluding Read-Only)"
      query = query.activity_dashboard_logs_by_service
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Events (Excluding Read-Only)"
      query = query.activity_dashboard_logs_by_event
      type  = "table"
      width = 6
    }

  }

}

# Query definitions

query "activity_dashboard_total_logs" {
  title = "Log Count"

  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      aws_cloudtrail_log;
  EOQ
}

query "activity_dashboard_logs_by_source_ip" {
  title = "Top 10 Source IPs (Non-AWS)"

  sql = <<-EOQ
    select
      tp_source_ip as "Source IP",
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    where
      tp_source_ip not like '%amazonaws.com'
      and tp_source_ip != 'AWS Internal'
    group by
      tp_source_ip
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_actor" {
  title = "Top 10 Actors (Non-AWS)"

  sql = <<-EOQ
    select
      user_identity.arn as "Actor",
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    where
      user_identity.type != 'AWSService'
      and user_identity.arn not like '%AWSServiceRole%'
    group by
      user_identity.arn
    order by
      count(*) desc
    limit 10;
  EOQ
}


query "activity_dashboard_logs_by_service" {
  title = "Top 10 Services"

  sql = <<-EOQ
    select
      event_source as "Service",
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    where
      not read_only
    group by
      event_source
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_event" {
  title = "Top 10 Events"

  sql = <<-EOQ
    select
      string_split(event_source, '.')[1] || ':' || event_name as "Event",
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    where
      not read_only
    group by
      "Event"
    order by
      count(*) desc
    limit 10;
  EOQ
}


query "activity_dashboard_logs_by_account" {
  title = "Activity by Account"

  sql = <<-EOQ
    select
      recipient_account_id,
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    group by
      recipient_account_id
    order by
      count(*) desc;
  EOQ
}

query "activity_dashboard_logs_by_region" {
  title = "Activity by Region"

  sql = <<-EOQ
    select
      aws_region,
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    group by
      aws_region
    order by
      count(*) desc;
  EOQ
}
