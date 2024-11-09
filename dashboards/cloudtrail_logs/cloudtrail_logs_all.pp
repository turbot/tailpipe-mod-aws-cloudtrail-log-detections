dashboard "cloudtrail_logs_all" {

  title         = "CloudTrail Logs"
  #documentation = file("./dashboards/ec2/docs/ec2_instance_detail.md")

  tags = merge(local.cloudtrail_logs_common_tags, {
    type = "Report"
  })

  container {

    input "detection_range" {
      title = "Select the date range:"
      type  = "date_range"
      width = 4
      # TODO: Do we need this sql arg?
      sql   = "select 1;"
    }

  }

  container {

    card {
      query = query.cloudtrail_logs_all_total_count
      width = 3
    }

  }

  container {

    table {
      query = query.cloudtrail_logs_all_with_principal

      column "principal_id" {
        href = "/aws.dashboard.cloudtrail_logs_search_by_principal_id?input.principal_id={{ .'principal_id' | @uri }}"
      }

      column "source_ip" {
        href = "/aws.dashboard.cloudtrail_logs_search_by_source_ip?input.source_ip={{ .'source_ip' | @uri }}"
      }

      column "source_id" {
        href = "/aws.dashboard.cloudtrail_logs_search_by_tp_id?input.tp_id={{ .'source_id' | @uri }}"
      }

      /*
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
      */

    }

  }

}

query "cloudtrail_logs_all_with_principal" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      string_split(event_source, '.')[1] || ':' || event_name as operation,
      --__RESOURCE_SQL__ as resource,
      user_identity.arn as actor,
      tp_source_ip as source_ip,
      tp_index::varchar as account_id,
      aws_region as region,
      tp_id as source_id,
      *
    from
      aws_cloudtrail_log
    order by
      event_time desc
      --event_time asc
    limit 10;
  EOQ
}

query "cloudtrail_logs_all_total_count" {
  sql = <<-EOQ
    select
      'Log count' as label,
      count(*) as value
    from
      aws_cloudtrail_log
  EOQ
}
