dashboard "aws_lambda_function_crud_event" {

  tags = {
    service          = "AWS/Lambda"
    mitre_attack_ids = "TA0005:T1525"
  }

  title = "AWS Lambda Function CRUD Event"

  container {
    table {
      query = query.aws_lambda_function_crud_event

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


query "aws_lambda_function_crud_event" {
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
      event_source = 'lambda.amazonaws.com'
      and event_name in ('AddPermission', 'CreateAlias', 'CreateEventSourceMapping', 'CreateFunction', 'DeleteAlias', 'DeleteEventSourceMapping','DeleteFunction', 'PublishVersion', 'RemovePermission', 'UpdateAlias', 'UpdateEventSourceMapping', 'UpdateFunctionCode', 'UpdateFunctionConfiguration')
      and (user_identity ->> 'arn') like '%DeployRole' 
    order by
      event_time desc;
  EOQ
}
