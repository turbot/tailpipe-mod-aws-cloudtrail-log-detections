locals {
  mitre_v151_ta0010_t1020_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1020"
  })

  cloudtrail_logs_detect_automated_s3_data_exfiltration_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0010_t1020" {
  title         = "T1020 Automated Exfiltration"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0010_t1020.md")
  children = [
    detection.cloudtrail_logs_detect_automated_s3_data_exfiltration
  ]

  tags = local.mitre_v151_ta0010_t1020_common_tags
}

detection "cloudtrail_logs_detect_automated_s3_data_exfiltration" {
  title       = "Detect Automated S3 Data Exfiltration"
  description = "Detect a high volume of S3 GET requests indicative of automated exfiltration."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_automated_s3_data_exfiltration.md")
  query       = query.cloudtrail_logs_detect_automated_s3_data_exfiltration

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

query "cloudtrail_logs_detect_automated_s3_data_exfiltration" {
  sql = <<-EOQ
    with request_counts as (
      select
        ${local.cloudtrail_logs_detect_automated_s3_data_exfiltration_sql_columns},
        count(*) over (
          partition by source_ip_address 
          order by event_time 
          rows between unbounded preceding and current row
        ) as request_count,
        event_time
      from
        aws_cloudtrail_log
      where
        event_source = 's3.amazonaws.com'
        and event_name = 'GetObject'
        and error_code IS NULL
    )
    select *
    from request_counts
    where request_count > 100
    order by event_time desc;
  EOQ
}
