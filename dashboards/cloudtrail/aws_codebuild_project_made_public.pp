dashboard "aws_codebuild_project_made_public" {

  tags = {
    service          = "AWS/CodeBuild"
    // TODO: add severity tags
    mitre_attack_ids = "TA0010:T1567"
  }

  title = "AWS CodeBuild Project Made Public"

  container {
    table {
      query = query.aws_codebuild_project_made_public

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
query "aws_codebuild_project_made_public" {
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
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProjectVisibility'
      and (request_parameters::json ->> 'projectVisibility') = 'PUBLIC_READ'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
