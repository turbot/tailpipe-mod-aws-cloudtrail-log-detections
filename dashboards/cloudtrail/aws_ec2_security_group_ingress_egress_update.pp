dashboard "aws_ec2_security_group_ingress_egress_update" {

  tags = {
    service = "AWS/EC2"
  }

  title         = "AWS EC2 Security Group Ingress/Egress Update"
  #documentation = file("./dashboards/iam/docs/iam_user_report_mfa.md")

  /*
  container {

    card {
      query = query.codespaces_delete_count
      width = 3
    }

    card {
      query = query.environment_delete_count
      width = 3
    }

    card {
      query = query.project_delete_count
      width = 3
    }

    card {
      query = query.repo_destroy_count
      width = 3
    }
  }

 */

 container {

  table {
    /*
    column "Actor" {
      #display = "none"
    }

    column "Action" {
      #display = "none"
    }

    column "Timestamp" {
      #display = "none"
      #href = "${dashboard.iam_user_detail.url_path}?input.user_arn={{.ARN | @uri}}"
    }

    column "Repository" {
      #display = "none"
      #href = "${dashboard.iam_user_detail.url_path}?input.user_arn={{.ARN | @uri}}"
    }

    column "Environment" {
      #display = "none"
      #href = "${dashboard.iam_user_detail.url_path}?input.user_arn={{.ARN | @uri}}"
    }

    column "Project" {
      #display = "none"
      #href = "${dashboard.iam_user_detail.url_path}?input.user_arn={{.ARN | @uri}}"
    }

    column "Organization" {
      #display = "none"
    }
    */

    query = query.aws_ec2_security_group_ingress_egress_update
  }

}
}

// TODO: Use normalized timestamp column
query "aws_ec2_security_group_ingress_egress_update" {
  sql = <<-EOQ
    select
      epoch_ms(event_time) as event_time,
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

/*
query "codespaces_delete_count" {
  sql = <<-EOQ
    select
      count(*) as value,
      'codespaces.delete' as label,
      case count(*) when 0 then 'ok' else 'alert' end as "type"
    from
      aws_audit_log
    where
      action = 'codespaces.delete';
  EOQ
}

query "environment_delete_count" {
  sql = <<-EOQ
    select
      count(*) as value,
      'environment.delete' as label,
      case count(*) when 0 then 'ok' else 'alert' end as "type"
    from
      aws_audit_log
    where
      action = 'environment.delete';
  EOQ
}

query "project_delete_count" {
  sql = <<-EOQ
    select
      count(*) as value,
      'project.delete' as label,
      case count(*) when 0 then 'ok' else 'alert' end as "type"
    from
      aws_audit_log
    where
      action = 'project.delete';
  EOQ
}

query "repo_destroy_count" {
  sql = <<-EOQ
    select
      count(*) as value,
      'repo.destroy' as label,
      case count(*) when 0 then 'ok' else 'alert' end as "type"
    from
      aws_audit_log
    where
      action = 'repo.destroy';
  EOQ
}
*/
