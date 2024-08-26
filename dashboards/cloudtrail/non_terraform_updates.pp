dashboard "cloudtrail_log_non_terraform_updates" {

  title         = "CloudTrail Logs Non-Terraform Updates"
  #documentation = file("./dashboards/ec2/docs/ec2_instance_detail.md")

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Report"
  })

  container {
    table {
      query = query.cloudtrail_log_non_terraform_updates_with_principal

      column "principal_id" {
        href = "/aws.dashboard.cloudtrail_log_search_by_principal_id?input.principal_id={{ .'principal_id' | @uri }}"
      }

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

// TODO: How to improve reasons when context could be from request_parameters, resources, tp_akas, etc., that often have different keys?
// Sample user agent strings from TF:
// APN/1.0 HashiCorp/1.0 Terraform/0.15.5 (+https://www.terraform.io) terraform-provider-aws/3.75.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.43.17 (go1.16; linux; amd64) exec-env/AWS_ECS_EC2
// APN/1.0 HashiCorp/1.0 Terraform/0.15.5 (+https://www.terraform.io) terraform-provider-aws/5.14.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.328 (go1.20.7; darwin; amd64)
query "cloudtrail_log_non_terraform_updates_with_principal" {
  sql = <<-EOQ
    select
      to_timestamp(event_time/1000)::timestamptz as event_time,
      tp_id,
      event_name,
      user_identity.principal_id as principal_id,
      user_identity.arn as user_arn,
      source_ip_address,
      aws_region as region,
      recipient_account_id as account_id,
      user_agent,
      --user_identity,
      --request_parameters,
      --response_elements,
      --additional_event_data,
      --resources,
    from
      aws_cloudtrail_log
    where
      user_agent not ilike '%Terraform/%'
      and user_identity.type != 'AWSService'
      and not read_only
      and error_code is null
    order by
      event_time desc;
  EOQ
}
