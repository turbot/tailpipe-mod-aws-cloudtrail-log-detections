locals {
  all_controls_common_tags = merge(local.aws_common_tags, {
    type = "Benchmark"
  })
}

benchmark "all_controls" {
  title       = "All Controls"
  description = "This benchmark contains all controls grouped by log type to help you detect high risk activities."
  children = [
    benchmark.all_controls_cloudtrail_log_checks
  ]

  tags = local.all_controls_common_tags
}

benchmark "all_controls_cloudtrail_log_checks" {
  title       = "CloudTrail Log Checks"
  description = "This section contains recommendations for scanning CloudTrail logs."
  children = [
    control.cloudtrail_log_cloudtrail_trail_updates,
    control.cloudtrail_log_ec2_security_group_ingress_egress_updates,
    control.cloudtrail_log_iam_root_console_logins,
    control.cloudtrail_log_non_read_only_updates,
    control.cloudtrail_log_non_terraform_updates,
  ]

  tags = merge(local.all_controls_common_tags, {
    service = "AWS/CloudTrail"
  })
}
