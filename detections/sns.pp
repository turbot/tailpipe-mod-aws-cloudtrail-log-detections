locals {
  sns_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SNS"
  })
}

benchmark "sns_detections" {
  title       = "SNS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SNS events."
  type        = "detection"
  children = [
    detection.sns_topic_granted_public_access,
  ]

  tags = merge(local.sns_common_tags, {
    type    = "Benchmark"
  })
}

detection "sns_topic_granted_public_access" {
  title           = "SNS Topic Granted Public Access"
  description     = "Detect when public access was granted to an SNS topic, potentially allowing unauthorized access and exposing sensitive notifications to external entities."
  documentation   = file("./detections/docs/sns_topic_granted_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.sns_topic_granted_public_access

  tags = merge(local.sns_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "sns_topic_granted_public_access" {
  sql = <<-EOQ
    with policy as (
      select
        *
      from
        aws_cloudtrail_log
      where
        event_source = 'sns.amazonaws.com'
        and event_name = 'SetTopicAttributes'
        and (request_parameters ->> 'attributeName') = 'Policy'
    )
    select
      ${local.detection_sql_resource_column_request_parameters_topic_arn},
      (item -> 'unnest') as statement
    from
      policy,
      unnest(
        from_json((request_parameters ->> 'attributeValue' -> 'Statement'), '["JSON"]')
      ) as item
    where
      (statement ->> 'Effect') = 'Allow'
      and (json_contains((statement -> 'Principal'), '{"AWS":"*"}'))
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
