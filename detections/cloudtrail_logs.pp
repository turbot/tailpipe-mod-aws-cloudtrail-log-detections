benchmark "cloudtrail_log_detections" {
  title       = "CloudTrail Log Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs."
  type        = "detection"
  children = [
    benchmark.apigateway_detections,
    benchmark.cloudfront_detections,
    benchmark.cloudtrail_detections,
    benchmark.cloudwatch_detections,
    benchmark.codebuild_detections,
    benchmark.config_detections,
    benchmark.ebs_detections,
    benchmark.ec2_detections,
    benchmark.efs_detections,
    benchmark.eventbridge_detections,
    benchmark.guardduty_detections,
    benchmark.iam_detections,
    benchmark.kms_detections,
    benchmark.lambda_detections,
    benchmark.rds_detections,
    benchmark.route53_detections,
    benchmark.s3_detections,
    benchmark.ses_detections,
    benchmark.ssm_detections,
    benchmark.sns_detections,
    benchmark.sqs_detections,
    benchmark.vpc_detections,
    benchmark.waf_detections,
  ]

  tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    type = "Benchmark"
  })
}
