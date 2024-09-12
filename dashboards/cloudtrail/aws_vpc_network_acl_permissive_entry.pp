dashboard "aws_vpc_network_acl_permissive_entry" {

  tags = {
    service          = "AWS/VPC"
    severity         = "Medium"
    mitre_attack_ids = "TA0003:T1098"
  }

  title = "AWS VPC Network ACL Permissive Entry"

  container {
    table {
      query = query.aws_vpc_network_acl_permissive_entry

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

      column "user_arn" {
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

// TODO: Use normalized timestamp column
query "aws_vpc_network_acl_permissive_entry" {
  sql = <<-EOQ
    select
      epoch_ms(event_time) as event_time,
      event_name,
      user_identity.arn as user_arn,
      source_ip_address,
      aws_region,
      recipient_account_id as account_id,
      user_agent,
      additional_event_data,
      request_parameters,
      response_elements,
      service_event_details,
      resources,
      user_identity
    from
      aws_cloudtrail_log
    where
      event_name = 'CreateNetworkAclEntry'
      and (request_parameters::json ->> 'cidrBlock') = '0.0.0.0/0'
      and (request_parameters::json ->> 'ruleAction') = 'allow'
      and (request_parameters::json ->> 'egress') = 'False'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
