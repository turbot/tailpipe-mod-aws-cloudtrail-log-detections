locals {
  all_controls_common_tags = merge(local.aws_common_tags, {
    type = "Benchmark"
  })
}

benchmark "all_controls" {
  title       = "All Controls"
  description = "This benchmark contains all controls grouped by log type to help you detect resource configurations that do not meet best practices."
  children = [
    benchmark.all_controls_cloudtrail_log
  ]

  tags = local.all_controls_common_tags
}
