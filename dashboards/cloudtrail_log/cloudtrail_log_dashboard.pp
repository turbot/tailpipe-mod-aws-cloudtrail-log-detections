dashboard "aws_cloudtrail_log_dashboard" {

  title = "CloudTrail Log Dashboard"

  tags = {
    type = "Dashboard"
    service = "AWS/CloudTrail"
  }

  container {

    input "detection_range" {
      title = "Select the date range:"
      type  = "date_range"
      width = 12
    }

  }

  container {

    # Analysis
    card {
      query = query.cloudtrail_log_total_logs
      width = 2
    }

  }

  container {

    chart {
      title = "Logs by Region"
      query = query.cloudtrail_log_logs_by_region
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Date"
      query = query.cloudtrail_log_logs_by_date
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Hour"
      query = query.cloudtrail_log_logs_by_hour
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Source IPs (Excluding AWS Services and Internal)"
      query = query.cloudtrail_log_logs_by_source_ip
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Actors (Excluding AWS Services)"
      query = query.cloudtrail_log_logs_by_actor
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Services (Excluding Read-Only)"
      query = query.cloudtrail_log_logs_by_service
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Events (Excluding Read-Only)"
      query = query.cloudtrail_log_logs_by_event
      type  = "table"
      width = 6
    }

  }

}

# Query Definitions

query "cloudtrail_log_total_logs" {
  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      aws_cloudtrail_log;
  EOQ
}

query "cloudtrail_log_logs_by_source_ip" {
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

query "cloudtrail_log_logs_by_actor" {
  sql = <<-EOQ
    select
      user_identity.arn as "Actor",
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    where
      user_identity.type != 'AWSService'
      and user_identity.arn not like '%AWSServiceRole%'
      and user_identity.arn not like '%assumed-role/turbot_%'
    group by
      user_identity.arn
    order by
      count(*) desc
    limit 10;
  EOQ
}


query "cloudtrail_log_logs_by_service" {
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

query "cloudtrail_log_logs_by_event" {
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


query "cloudtrail_log_logs_by_region" {
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

query "cloudtrail_log_logs_by_date" {
  sql = <<-EOQ
    select
      datetrunc('day', tp_timestamp) as log_date,
      --strftime('%Y-%m-%d', tp_timestamp) as date_only,
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    group by
      log_date
    order by
      log_date;
  EOQ
}

query "cloudtrail_log_logs_by_hour" {
  sql = <<-EOQ
    select
      datetrunc('hour', tp_timestamp) as log_date,
      count(*) as "Logs"
    from
      aws_cloudtrail_log
    group by
      log_date
    order by
      log_date;
  EOQ
}
