dashboard "cloudtrail_logs_error_report" {

  title         = "CloudTrail Logs Error Report"

  tags = {
    type = "Report"
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

    card {
      query = query.cloudtrail_log_error_report_total_errors
      width = 3
    }

  }

  container {

    table {
      query = query.cloudtrail_log_error_report_table

      column "actor" {
        wrap = "all"
      }

      column "error_message" {
        wrap = "all"
      }

      /*
      column "principal_id" {
        href = "/aws.dashboard.cloudtrail_logs_search_by_principal_id?input.principal_id={{ .'principal_id' | @uri }}"
      }

      column "source_ip" {
        href = "/aws.dashboard.cloudtrail_logs_search_by_source_ip?input.source_ip={{ .'source_ip' | @uri }}"
      }

      column "source_id" {
        href = "/aws.dashboard.cloudtrail_logs_search_by_tp_id?input.tp_id={{ .'source_id' | @uri }}"
      }

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

query "cloudtrail_log_error_report_table" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      string_split(event_source, '.')[1] || ':' || event_name as operation,
      --__RESOURCE_SQL__ as resource,
      user_identity.arn as actor,
      tp_source_ip as source_ip,
      tp_index::varchar as account_id,
      aws_region as region,
      error_code,
      error_message,
      tp_id as source_id,
      *
    from
      aws_cloudtrail_log
    where
      error_code is not null
    order by
      timestamp desc;
  EOQ
}

query "cloudtrail_log_error_report_total_errors" {
  sql = <<-EOQ
    select
      count(*) as "Total Errors"
    from
      aws_cloudtrail_log
    where
      error_code is not null;
  EOQ
}
