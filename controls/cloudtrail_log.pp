locals {
  cloudtrail_log_common_tags = merge(local.aws_common_tags, {
    service = "AWS/CloudTrail"
  })
}

// TODO: Singular or plural for "login"?
control "cloudtrail_log_console_root_login" {
  title       = "Check CloudTrail Logs for Console Root Login"
  description = "Logging in as root is not recommended due to the high privilege level."
  severity    = "high"
  query       = query.cloudtrail_log_console_root_login

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_tactic    = "Initial Access"
    mitre_tactic_id = "TA0001"
    mitre_attack    = "Valid Accounts"
    mitre_attack_id = "T1078"
  })
}

control "cloudtrail_log_cloudtrail_trail_updates" {
  title       = "Check CloudTrail Logs for CloudTrail Trail Updates"
  description = "Modifying CloudTrail trails can affect logging and exports of logs."
  severity    = "medium"
  query       = query.cloudtrail_log_cloudtrail_trail_updates

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_tactic    = "Defense Evasion"
    mitre_tactic_id = "TA0005"
    mitre_attack    = "Disable or Modify Tools"
    mitre_attack_id = "T1562.001"
  })
}

control "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  title       = "Check CloudTrail Logs for EC2 Security Group Ingress/Egress Updates"
  description = "Modifying EC2 security group rules can allow for unauthorized VPC access or export of data."
  severity    = "medium"
  query       = query.cloudtrail_log_ec2_security_group_ingress_egress_updates

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_tactic    = "Initial Access"
    mitre_tactic_id = "TA0001"
    mitre_attack    = "Exploit Public-Facing Application"
    mitre_attack_id = "T1190"
  })
}

control "cloudtrail_log_non_read_only_updates" {
  title       = "Check CloudTrail Logs for Non-Read Only Updates"
  description = "View all events that are not read-only."
  // TODO: What severity?
  severity    = "low"
  query       = query.cloudtrail_log_non_read_only_updates

  // TODO: What tags?
  /*
  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_tactic    = "Initial Access"
    mitre_tactic_id = "TA0001"
    mitre_attack    = "Exploit Public-Facing Application"
    mitre_attack_id = "T1190"
  })
  */
}

control "cloudtrail_log_non_terraform_updates" {
  title       = "Check CloudTrail Logs for Non-Terraform Updates"
  description = "API calls made outside of Terraform should be monitored."
  // TODO: What severity?
  severity    = "low"
  query       = query.cloudtrail_log_non_terraform_updates

  // TODO: What tags?
  /*
  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_tactic    = "Initial Access"
    mitre_tactic_id = "TA0001"
    mitre_attack    = "Exploit Public-Facing Application"
    mitre_attack_id = "T1190"
  })
  */
}

// TODO: Add more request param data to reason
query "cloudtrail_log_console_root_login" {
  sql = <<-EOQ
    install json;
    load json;
    select
      tp_id as resource,
      'alarm' as status,
      case
        when (additional_event_data::JSON ->> 'MFAUsed') = 'Yes' then 'AWS root console login with MFA from ' || tp_source_ip || ' in AWS account ' || recipient_account_id || '.'
        else 'AWS root console login from ' || tp_source_ip || ' in AWS account ' || recipient_account_id || '.'
      end as reason,
      (to_timestamp(tp_timestamp/1000)::timestamptz)::varchar as event_time,
      tp_id,
      -- TODO: Do we need to show usernames if the reason has the ARN?
      --tp_usernames::string,
      tp_source_ip,
      recipient_account_id,
      -- TODO: Region is the same for each partition, do we need it?
      aws_region,
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

// TODO: Add more request param data to reason
query "cloudtrail_log_cloudtrail_trail_updates" {
  sql = <<-EOQ
    install json;
    load json;
    select
      tp_id as resource,
      'alarm' as status,
      user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || ' for ' || (request_parameters::JSON ->> 'name') || '.' as reason,
      (to_timestamp(tp_timestamp/1000)::timestamptz)::varchar as event_time,
      tp_id,
      -- TODO: Do we need to show usernames if the reason has the ARN?
      --tp_usernames::string,
      tp_source_ip,
      recipient_account_id,
      aws_region,
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
    install json;
    load json;
    select
      tp_id as resource,
      'alarm' as status,
      user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || ' for ' || (request_parameters::JSON ->> 'groupId') || '.' as reason,
      (to_timestamp(tp_timestamp/1000)::timestamptz)::varchar as event_time,
      tp_id,
      -- TODO: Do we need to show usernames if the reason has the ARN?
      --tp_usernames::string,
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
    install json;
    load json;
    select
      tp_id as resource,
      'alarm' as status,
      case
        when tp_akas is not null then user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || ' for ' || tp_akas::string || '.'
        else user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || '.'
      end as reason,
      (to_timestamp(tp_timestamp/1000)::timestamptz)::varchar as event_time,
      tp_id,
      -- TODO: Do we need to show usernames if the reason has the ARN?
      --tp_usernames::string,
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
    install json;
    load json;
    select
      tp_id as resource,
      'alarm' as status,
      case
        when tp_akas is not null then user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || ' for ' || tp_akas::string || '.'
        else user_identity.arn || ' called ' || string_split(event_source, '.')[1] || ':' || event_name || '.'
      end as reason,
      (to_timestamp(tp_timestamp/1000)::timestamptz)::varchar as event_time,
      tp_id,
      -- TODO: Do I need to see user_agent all the time?
      --user_agent,
      -- TODO: Do we need to show usernames if the reason has the ARN?
      --tp_usernames::string,
      tp_source_ip,
      recipient_account_id,
      aws_region,
      --request_parameters::string,
      --response_elements::string,
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

