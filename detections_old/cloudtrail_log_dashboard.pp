/*
dashboard "test_cloudtrail_log_detections" {

  detection_benchmark "cloudtrail_log_checks_test" {
    title       = "CloudTrail Log Checks Dashboard"
    description = "This detection list contains recommendations when scanning CloudTrail logs."
    children = [
      detection_benchmark.cloudtrail_log_checks_ec2
    ]

    tags = merge(local.cloudtrail_log_common_tags, {
      type = "Benchmark"
    })
  }

}
*/
