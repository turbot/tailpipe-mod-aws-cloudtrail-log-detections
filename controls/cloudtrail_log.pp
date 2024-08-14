locals {
  cloudtrail_log_common_tags = merge(local.aws_common_tags, {
    service = "AWS/CloudTrail"
  })
}

control "cloudtrail_log_ec2_security_group_ingress_egress_update" {
  title       = "Check for CloudTrail Log EC2 Security Group Ingress/Egress Updates"
  description = "Check for EC2 security group ingress and egress rule updates in CloudTrail logs."
  query       = query.cloudtrail_log_ec2_security_group_ingress_egress_update

  tags = local.cloudtrail_log_common_tags
}

// TODO: Fix reason and add row data
query "cloudtrail_log_ec2_security_group_ingress_egress_update" {
  sql = <<-EOQ
    select
      event_id as resource,
      'alarm' as status,
      user_identity.arn || ' updated ' || request_parameters.groupId || ' with ' || event_name || ' on ' || to_timestamp(event_time/1000)::timestamptz || '.' as reason,
      to_timestamp(event_time/1000)::timestamptz as event_time,
      event_name,
      user_identity.arn as user_arn,
      source_ip_address,
      aws_region,
      recipient_account_id as account_id,
      user_agent,
      request_parameters,
      response_elements,
      additional_event_data,
      service_event_details,
      resources,
      user_identity
    from
      aws_cloudtrail_log
    where
      --user_identity.type = 'user'
      --event_type = 'AwsServiceEvent'
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupEgress', 'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'RevokeSecurityGroupIngress')
      --and not read_only
    order by
      event_time desc;
  EOQ
}
