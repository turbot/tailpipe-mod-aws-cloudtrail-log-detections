locals {
  cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_cloudfront_detections" {
  title       = "CloudFront Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's CloudFront logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled,
    detection.cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled,
    detection.cloudtrail_logs_detect_cloudfront_distribution_deletions,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/CloudFront"
  })
}

detection "cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled" {
  title       = "Detect CloudFront ACL or Access Control Changes"
  description = "Identify updates to CloudFront Access Control Lists (ACLs) or changes in Origin Access Identity."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.004"
  })
}

query "cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_log_detection_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name in ('UpdateDistribution', 'CreateDistribution')
      and (
        request_parameters.viewer_certificate.cloudfront_default_certificate != 'true'
      )
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled" {
  title       = "Detect CloudFront Distributions with Geo-restriction disabled"
  description = "Identify updates to CloudFront Access Control Lists (ACLs) or changes in Origin Access Identity."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.004"
  })
}

query "cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_log_detection_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and (
        request_parameters.restrictions.geo_restriction.restriction_type != 'none'
      )
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins" {
  title       = "Detect Overly Permissive CloudFront Origins"
  description = "Identify CloudFront origins that allow public access, which can enable data exfiltration."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1071"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_log_detection_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name in ('CreateDistribution', 'UpdateDistribution')
      and request_parameters.origins.items[*].s3_origin_config.origin_access_identity is null
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled" {
  title       = "Detect CloudFront Logging Disabled"
  description = "Identify attempts to disable logging on CloudFront distributions."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.002"
  })
}

query "cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_log_detection_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and request_parameters.logging.enabled = 'false'
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudfront_distribution_deletions" {
  title       = "Detect CloudFront Distribution Deletions"
  description = "Identify events where CloudFront distributions are deleted, potentially disrupting content delivery."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_cloudfront_distribution_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "cloudtrail_logs_detect_cloudfront_distribution_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_log_detection_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'DeleteDistribution'
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified" {
  title       = "Detect CloudFront Origin Failover Changes"
  description = "Identify updates to origin failover settings that can redirect data exfiltration."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

query "cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_log_detection_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and request_parameters.origins.items[*].failover_criteria.status_codes is not null
    order by
      event_time desc;
  EOQ
}
