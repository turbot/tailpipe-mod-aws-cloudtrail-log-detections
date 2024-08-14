locals {
  all_controls_cloudtrail_log_common_tags = merge(local.all_controls_common_tags, {
    service = "AWS/CloudTrail"
  })
}

benchmark "all_controls_cloudtrail_log" {
  title       = "CloudTrail Logs"
  description = "This section contains recommendations for scanning CloudTrail logs."
  children = [
    control.cloudtrail_log_ec2_security_group_ingress_egress_update
  ]

  tags = merge(local.all_controls_cloudtrail_log_common_tags, {
    type = "Benchmark"
  })
}
