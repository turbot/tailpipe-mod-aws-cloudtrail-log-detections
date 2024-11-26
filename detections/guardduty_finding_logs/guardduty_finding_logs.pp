locals {
  guardduty_finding_log_detection_common_tags = merge(local.aws_detections_common_tags, {
    service = "AWS/GuardDuty"
  })
}

detection_benchmark "guardduty_finding_log_detections" {
  title       = "GuardDuty Finding Log Detections"
  description = "This detection_benchmark contains recommendations when scanning GuardDuty finding logs."
  type        = "detection"

  children = [
    detection.guardduty_finding_logs_with_low_severity,
    detection.guardduty_finding_logs_with_medium_severity,
    detection.guardduty_finding_logs_with_high_severity
  ]

  tags = merge(local.guardduty_finding_log_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "guardduty_finding_logs_with_low_severity" {
  title       = "Detect Low Severity Finding"
  description = "This detection will alert when a low severity finding is detected."
  severity    = "low"
  query       = query.guardduty_finding_logs_with_low_severity

  tags = local.guardduty_finding_log_detection_common_tags
}

detection "guardduty_finding_logs_with_medium_severity" {
  title       = "Detect Medium Severity Finding"
  description = "This detection will alert when a medium severity finding is detected."
  severity    = "medium"
  query       = query.guardduty_finding_logs_with_medium_severity

  tags = local.guardduty_finding_log_detection_common_tags
}

detection "guardduty_finding_logs_with_high_severity" {
  title       = "Detect High Severity Finding"
  description = "This detection will alert when a high severity finding is detected."
  severity    = "high"
  query       = query.guardduty_finding_logs_with_high_severity

  tags = local.guardduty_finding_log_detection_common_tags
}

query "guardduty_finding_logs_with_low_severity" {
  sql = <<-EOQ
    select
      ${local.guardduty_finding_log_detection_sql_columns}
    from
      aws_guardduty_finding
    where
      cast(severity as double) between 0.1 and 3.9
    order by
      timestamp desc
  EOQ
}

query "guardduty_finding_logs_with_medium_severity" {
  sql = <<-EOQ
    select
      ${local.guardduty_finding_log_detection_sql_columns}
    from
      aws_guardduty_finding
    where
      cast(severity as double) between 4.0 and 6.9
    order by
      timestamp desc
  EOQ
}

query "guardduty_finding_logs_with_high_severity" {
  sql = <<-EOQ
    select
      ${local.guardduty_finding_log_detection_sql_columns}
    from
      aws_guardduty_finding
    where
      cast(severity as double) between 7.0 and 8.9
    order by
      timestamp desc
  EOQ
}
