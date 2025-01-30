locals {
  cloudfront_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CloudFront"
  })

}

benchmark "cloudfront_detections" {
  title       = "CloudFront Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudFront events."
  type        = "detection"
  children = [
    detection.cloudfront_distribution_default_certificate_disabled,
    detection.cloudfront_distribution_logging_disabled,
  ]

  tags = merge(local.cloudfront_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudfront_distribution_default_certificate_disabled" {
  title           = "CloudFront Distribution Default Certificate Disabled"
  description     = "Detect when a CloudFront distribution's default certificate was disabled to check for misconfigurations that could lead to insecure connections or unauthorized access, compromising data integrity and security."
  documentation   = file("./detections/docs/cloudfront_distribution_default_certificate_disabled.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.cloudfront_distribution_default_certificate_disabled

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudfront_distribution_default_certificate_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name in ('UpdateDistribution', 'CreateDistribution')
      and (request_parameters -> 'distributionConfig' -> 'viewerCertificate' -> 'cloudFrontDefaultCertificate') = false
    order by
      event_time desc;
  EOQ
}

detection "cloudfront_distribution_logging_disabled" {
  title           = "CloudFront Distribution Logging Disabled"
  description     = "Detect when a CloudFront distribution's logging was disabled to check for changes that could hinder monitoring and auditing, potentially obscuring malicious activity or misconfigurations."
  documentation   = file("./detections/docs/cloudfront_distribution_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudfront_distribution_logging_disabled

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.002"
  })
}

query "cloudfront_distribution_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and (request_parameters -> 'distributionConfig' -> 'logging' -> 'enabled') = false
    order by
      event_time desc;
  EOQ
}
