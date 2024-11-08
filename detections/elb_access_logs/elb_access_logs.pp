locals {
  elb_access_logs_common_tags = merge(local.aws_common_tags, {
    service = "AWS/ELB"
  })
}

detection_benchmark "elb_access_log_detections" {
  title       = "ELB Access Log Detections"
  description = "This detection_benchmark contains recommendations when scanning ELB access logs."
  type        = "detection"

  children = [
    detection.elb_access_logs_insecure_access,
  ]

  tags = merge(local.elb_access_logs_common_tags, {
    type = "Benchmark"
  })
}

detection "elb_access_logs_insecure_access" {
  title       = "Detect Insecure Access Requests in ELB Access Logs"
  description = "Detect insecure access requests to check for possible application misconfigurations."
  severity    = "high"
  query       = query.elb_access_logs_insecure_access

  tags = local.elb_access_logs_common_tags
}

query "elb_access_logs_insecure_access" {
  sql = <<-EOQ
    select
      ${local.common_dimensions_elb_access_logs_sql}
    from
      aws_elb_access_log
    where
      type = 'https'
      and (ssl_cipher= '-' or ssl_protocol = '-')
    order by
      timestamp desc
  EOQ
}
