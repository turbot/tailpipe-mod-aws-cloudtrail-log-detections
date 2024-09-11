dashboard "aws_rds_db_instance_public_restore" {

  tags = {
    service          = "AWS/RDS"
    mitre_attack_ids = "TA0010:T1020"
  }

  title = "AWS RDS DB Instance Public Restore"

  container {
    table {
      query = query.aws_rds_db_instance_public_restore

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
query "aws_rds_db_instance_public_restore" {
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
      event_source = 'rds.amazonaws.com'
      and event_name = 'RestoreDBInstanceFromDBSnapshot'
      and (response_elements::json ->> 'publiclyAccessible') = 'true' 
    order by
      event_time desc;
  EOQ
}
