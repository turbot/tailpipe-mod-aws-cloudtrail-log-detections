locals {
  cloudtrail_log_common_tags = merge(local.aws_common_tags, {
    service = "AWS/CloudTrail"
  })
}

detection_benchmark "cloudtrail_log_checks" {
  title       = "CloudTrail Log Detections"
  description = "This detection_benchmark contains recommendations when scanning CloudTrail logs."
  children = [
    detection.cloudtrail_log_cloudtrail_trail_updates,
    detection.cloudtrail_log_ec2_security_group_ingress_egress_updates,
    detection.cloudtrail_log_iam_root_console_logins,
    detection.cloudtrail_log_non_read_only_updates,
    detection.cloudtrail_log_non_terraform_updates,
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_log_iam_root_console_logins" {
  title       = "Check CloudTrail Logs for IAM Root Console Logins"
  description = "Detect IAM root user console logins to check for any actions performed by the root user."
  severity    = "high"
  query       = query.cloudtrail_log_iam_root_console_logins

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_log_cloudtrail_trail_updates" {
  title       = "Check CloudTrail Logs for CloudTrail Trail Updates"
  description = "Detect CloudTrail trail changes to check if logging was stopped."
  severity    = "medium"
  query       = query.cloudtrail_log_cloudtrail_trail_updates

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0005:T1562:001"
  })
}

detection "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  title       = "Check CloudTrail Logs for EC2 Security Group Ingress/Egress Updates"
  description = "Detect EC2 security group ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity    = "medium"
  query       = query.cloudtrail_log_ec2_security_group_ingress_egress_updates

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
}

detection "cloudtrail_log_non_read_only_updates" {
  title       = "Check CloudTrail Logs for Non-Read-Only Updates"
  description = "Detect write events that are performed by a non-AWS service."
  // TODO: What severity?
  severity    = "low"
  query       = query.cloudtrail_log_non_read_only_updates

  tags = local.cloudtrail_log_common_tags
}

detection "cloudtrail_log_non_terraform_updates" {
  title       = "Check CloudTrail Logs for Non-Terraform Updates"
  description = "Detect write events that are performed by a non-AWS service and without Terraform."
  // TODO: What severity?
  severity    = "low"
  query       = query.cloudtrail_log_non_terraform_updates

  tags = local.cloudtrail_log_common_tags
}

query "cloudtrail_log_iam_root_console_logins" {
  sql = <<-EOQ
    select
      tp_id as resource,
      'alarm' as status,
      case
        when (additional_event_data::JSON ->> 'MFAUsed') = 'Yes' then 'AWS root console login with MFA from ' || tp_source_ip || ' in AWS account ' || recipient_account_id || '.'
        else 'AWS root console login from ' || tp_source_ip || ' in AWS account ' || recipient_account_id || '.'
      end as reason,
      (epoch_ms(tp_timestamp))::varchar as event_time,
      tp_id,
      tp_source_ip,
      recipient_account_id
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and user_identity.type = 'Root'
      and (response_elements::JSON ->> 'ConsoleLogin') = 'Success'
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_log_cloudtrail_trail_updates" {
  sql = <<-EOQ
    select
      tp_id as resource,
      'alarm' as status,
      user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || ' for ' || (request_parameters::JSON ->> 'name') || '.' as reason,
      (epoch_ms(tp_timestamp))::varchar as event_time,
      tp_id,
      tp_source_ip,
      recipient_account_id,
      aws_region
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name in ('DeleteTrail', 'StopLogging', 'UpdateTrail')
      and error_code is null
    order by
      event_time desc;
  EOQ
}


// TODO: Add more request param data to reason
query "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  sql = <<-EOQ
    select
      tp_id as resource,
      'alarm' as status,
      user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || ' for ' || (request_parameters::JSON ->> 'groupId') || '.' as reason,
      (epoch_ms(tp_timestamp))::varchar as event_time,
      tp_id,
      tp_source_ip,
      recipient_account_id,
      aws_region,
      (request_parameters::JSON).ipPermissions.items as rule_updates,
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupEgress', 'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'RevokeSecurityGroupIngress')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

// TODO: How to improve reasons when context could be from request_parameters, resources, tp_akas, etc., that often have different keys?
query "cloudtrail_log_non_read_only_updates" {
  sql = <<-EOQ
    select
      tp_id as resource,
      'alarm' as status,
      case
        when tp_akas is not null then user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || ' for ' || tp_akas::string || '.'
        else user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || '.'
      end as reason,
      (epoch_ms(tp_timestamp))::varchar as event_time,
      tp_id,
      tp_source_ip,
      recipient_account_id,
      aws_region,
      --request_parameters::string,
      --response_elements::string,
    from
      aws_cloudtrail_log
    where
      user_identity.type != 'AWSService'
      and not read_only
      and error_code is null
    order by
      event_time desc;
  EOQ
}

// TODO: How to improve reasons when context could be from request_parameters, resources, tp_akas, etc., that often have different keys?
// Sample user agent strings from TF:
// APN/1.0 HashiCorp/1.0 Terraform/0.15.5 (+https://www.terraform.io) terraform-provider-aws/3.75.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.43.17 (go1.16; linux; amd64) exec-env/AWS_ECS_EC2
// APN/1.0 HashiCorp/1.0 Terraform/0.15.5 (+https://www.terraform.io) terraform-provider-aws/5.14.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.328 (go1.20.7; darwin; amd64)
query "cloudtrail_log_non_terraform_updates" {
  sql = <<-EOQ
    select
      tp_id as resource,
      'alarm' as status,
      case
        when tp_akas is not null then user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || ' for ' || tp_akas::string || '.'
        else user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || '.'
      end as reason,
      (epoch_ms(tp_timestamp))::varchar as event_time,
      tp_id,
      tp_source_ip,
      recipient_account_id,
      aws_region,
      user_agent,
    from
      aws_cloudtrail_log
    where
      -- Should we use this instead to include Guardrails TF actions too?
      --user_agent not ilike '%terraform-provider-%'
      user_agent not ilike '%Terraform/%'
      and user_identity.type != 'AWSService'
      and not read_only
      and error_code is null
    order by
      event_time desc;
  EOQ
}
