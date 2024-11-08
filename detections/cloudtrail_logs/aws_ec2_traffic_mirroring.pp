dashboard "aws_ec2_traffic_mirroring" {

  tags = {
    service          = "AWS/EC2"
    severity         = "Medium"
    # TODO: verify the mitre attack ID
    mitre_attack_ids = "T1040"
  }

  title = "AWS EC2 Traffic Mirroring"

  container {
    table {
      query = query.aws_ec2_traffic_mirroring

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


query "aws_ec2_traffic_mirroring" {
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
      event_source = 'ec2.amazonaws.com'
      and event_name in ('CreateTrafficMirrorFilter', 'CreateTrafficMirrorFilterRule', 'CreateTrafficMirrorSession', 'CreateTrafficMirrorTarget', 'DeleteTrafficMirrorFilter', 'DeleteTrafficMirrorFilterRule', 'DeleteTrafficMirrorSession', 'DeleteTrafficMirrorTarget', 'ModifyTrafficMirrorFilterNetworkServices', 'ModifyTrafficMirrorFilterRule', 'ModifyTrafficMirrorSession')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
