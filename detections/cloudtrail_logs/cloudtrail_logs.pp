locals {
  cloudtrail_log_detection_common_tags = merge(local.aws_detections_common_tags, {
    service = "AWS"
  })
}

benchmark "cloudtrail_log_detections" {
  title       = "CloudTrail Log Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs."
  type        = "detection"
  children = [
    benchmark.cloudtrail_logs_apigateway_detections,
    benchmark.cloudtrail_logs_cloudfront_detections,
    benchmark.cloudtrail_logs_cloudtrail_detections,
    benchmark.cloudtrail_logs_cloudwatch_detections,
    benchmark.cloudtrail_logs_codebuild_detections,
    benchmark.cloudtrail_logs_config_detections,
    benchmark.cloudtrail_logs_ebs_detections,
    benchmark.cloudtrail_logs_ec2_detections,
    benchmark.cloudtrail_logs_efs_detections,
    benchmark.cloudtrail_logs_eventbridge_detections,
    benchmark.cloudtrail_logs_guardduty_detections,
    benchmark.cloudtrail_logs_iam_detections,
    benchmark.cloudtrail_logs_kms_detections,
    benchmark.cloudtrail_logs_lambda_detections,
    benchmark.cloudtrail_logs_rds_detections,
    benchmark.cloudtrail_logs_route53_detections,
    benchmark.cloudtrail_logs_s3_detections,
    benchmark.cloudtrail_logs_ses_detections,
    benchmark.cloudtrail_logs_ssm_detections,
    benchmark.cloudtrail_logs_sqs_detections,
    benchmark.cloudtrail_logs_vpc_detections,
    benchmark.cloudtrail_logs_waf_detections,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type = "Benchmark"
  })
}
