locals {
  guardduty_finding_log_detection_common_tags = merge(local.aws_detections_common_tags, {
    service = "AWS/GuardDuty"
  })
}

benchmark "guardduty_finding_log_detections" {
  title       = "GuardDuty Finding Log Detections"
  description = "This benchmark contains recommendations when scanning GuardDuty finding logs."
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
  description = "Detect low severity findings to check for possible security issues."
  severity    = "low"
  query       = query.guardduty_finding_logs_with_low_severity

  # references = [
  #   "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html#guardduty_findings-severity"
  # ]

  tags = local.guardduty_finding_log_detection_common_tags
}

detection "guardduty_finding_logs_with_medium_severity" {
  title       = "Detect Medium Severity Finding"
  description = "Detect medium severity findings to check for possible security issues."
  severity    = "medium"
  query       = query.guardduty_finding_logs_with_medium_severity

  # references = [
  #   "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html#guardduty_findings-severity"
  # ]

  tags = local.guardduty_finding_log_detection_common_tags
}

detection "guardduty_finding_logs_with_high_severity" {
  title       = "Detect High Severity Finding"
  description = "Detect high severity findings to check for possible security issues."
  severity    = "high"
  query       = query.guardduty_finding_logs_with_high_severity

  # references = [
  #   "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html#guardduty_findings-severity"
  # ]

  tags = local.guardduty_finding_log_detection_common_tags
}

query "guardduty_finding_logs_with_low_severity" {
  sql = <<-EOQ
    select
      ${local.guardduty_finding_log_detection_sql_columns}
    from
      aws_guardduty_finding
    where
      severity between 0.1 and 3.9
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
      severity between 4.0 and 6.9
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
      severity between 7.0 and 8.9
    order by
      timestamp desc
  EOQ
}
