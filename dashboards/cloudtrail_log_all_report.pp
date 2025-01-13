dashboard "cloudtrail_logs_all_report" {

  title         = "CloudTrail Logs Report"

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

  /*
  container {
    input "source_ip" {
      title = "Select a source IP address:"
      query = query.source_ip_input
      type  = "multiselect"
      width = 4
    }

    input "aws_region" {
      title = "Select a region:"
      query = query.aws_region_input
      type  = "multiselect"
      placeholder = "test"
      width = 4
    }
  }
  */

  container {
    card {
      query = query.cloudtrail_log_all_total_logs
      width = 2
      args  = [
        #self.input.source_ip.value,
        #self.input.aws_region.value
      ]
    }
  }

  container {

    table {
      query = query.cloudtrail_log_all_table

      args  = [
        #self.input.source_ip.value,
        #self.input.aws_region.value
      ]

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

query "cloudtrail_log_all_total_logs" {
  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      aws_cloudtrail_log
    --where
    --  tp_source_ip in $1
    --  and aws_region in $2
  EOQ
}

query "cloudtrail_log_all_table" {
  sql = <<-EOQ
    select
      --epoch_ms(tp_timestamp) as timestamp,
      --string_split(event_source, '.')[1] || ':' || event_name as operation,
      --user_identity.arn as actor,
      --tp_source_ip as source_ip,
      --tp_index::varchar as account_id,
      --aws_region as region,
      --error_code,
      --error_message,
      --tp_id as source_id,
      *
    from
      aws_cloudtrail_log
    --where
    --  tp_source_ip in $1
    --  and aws_region in $2
    order by
      tp_timestamp desc
      --timestamp desc
    limit 1000;
  EOQ
}

# Input queries

query "source_ip_input" {
  sql = <<-EOQ
    with source_ips as (
      select
        distinct(tp_source_ip) as source_ip
      from
      aws_cloudtrail_log
    )
    select
      source_ip as label,
      source_ip as value
    from
      source_ips
    order by
      source_ip;
  EOQ
}

query "aws_region_input" {
  sql = <<-EOQ
    with aws_regions as (
      select
        distinct(aws_region) as aws_region
      from
      aws_cloudtrail_log
    )
    select
      aws_region as label,
      aws_region as value
    from
      aws_regions
    order by
      aws_region;
  EOQ
}

