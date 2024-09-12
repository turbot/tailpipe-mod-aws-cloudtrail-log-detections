dashboard "aws_ec2_security_group_ingress_egress_update_detection" {

  tags = {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
    service          = "AWS/EC2"
    severity         = "medium"
  }

  title = "CloudTrail Logs - EC2 Security Group Ingress/Egress Update"

  container {
    table {
      query = query.aws_ec2_security_group_ingress_egress_update_detection

      column "additional_event_data" {
        wrap = "all"
      }

      column "request_parameters" {
        wrap = "all"
      }

      column "response_elements" {
        wrap = "all"
      }

      column "resources" {
        wrap = "all"
      }

      column "service_event_details" {
        wrap = "all"
      }

      column "user_agent" {
        wrap = "all"
      }

      column "user_identity" {
        wrap = "all"
      }

    }
  }
}

locals {
  # Store the replace logic in a local variable
  aws_ec2_security_group_ingress_egress_update_detection_sql = replace(local.common_dimensions_cloudtrail_log_sql, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'groupId'")
}

query "aws_ec2_security_group_ingress_egress_update_detection" {
  sql = <<-EOQ
    select
      ${local.aws_ec2_security_group_ingress_egress_update_detection_sql}
      -- Additional dimensions
      --additional_event_data,
      --request_parameters,
      --response_elements,
      --resources,
      --service_event_details,
      --user_agent,
      --user_identity
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
