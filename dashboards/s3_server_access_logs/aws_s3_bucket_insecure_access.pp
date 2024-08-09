dashboard "aws_s3_bucket_insecure_access" {

  tags = {
    service = "AWS/S3"
  }

  title         = "AWS S3 Bucket Insecure Access"
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

    query = query.aws_s3_bucket_insecure_access
  }

}
}

// TODO: Add region and account ID
query "aws_s3_bucket_insecure_access" {
  sql = <<-EOQ
    select
      timestamp,
      bucket,
      key,
      remote_ip,
      operation,
      requester,
      user_agent
    from
      aws_s3_server_access_log
    where
      cipher_suite is null
      or tls_version is null
    order by
      timestamp desc
    limit 3
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
