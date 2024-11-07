locals {
  all_detections_common_tags = merge(local.aws_common_tags, {
    type = "Benchmark"
  })
}

detection_benchmark "all_detections" {
  title       = "All Controls"
  description = "This detection_benchmark contains all detections grouped by log type to help you detect high risk activities."
  children = [
    detection_benchmark.all_detections_cloudtrail_log_checks
  ]

  tags = local.all_detections_common_tags
}

detection_benchmark "all_detections_cloudtrail_log_checks" {
  title       = "CloudTrail Log Checks"
  description = "This section contains recommendations for scanning CloudTrail logs."
  children = [
    detection.cloudtrail_log_cloudtrail_trail_updates,
    detection.cloudtrail_log_ec2_security_group_ingress_egress_updates,
    detection.cloudtrail_log_iam_root_console_logins,
    detection.cloudtrail_log_non_read_only_updates,
    detection.cloudtrail_log_non_terraform_updates,
  ]

  tags = merge(local.all_detections_common_tags, {
    service = "AWS/CloudTrail"
  })
}
