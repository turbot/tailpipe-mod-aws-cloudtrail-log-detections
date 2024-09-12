dashboard "aws_elb_insecure_access" {

  tags = {
    service = "AWS/ELB"
  }

  title         = "ELB Access Logs - Insecure Access"
  #documentation = file("./dashboards/iam/docs/iam_user_report_mfa.md")

   container {
    table {
      query = query.aws_elb_insecure_access
    }
  }
}

locals {
  # Store the replace logic in a local variable
  aws_elb_insecure_access_sql = replace(local.common_dimensions_elb_log_sql, "__RESOURCE_SQL__", "elb")
}

query "aws_elb_insecure_access" {
  sql = <<-EOQ
    select
      ${local.aws_elb_insecure_access_sql}
      -- Additional dimensions
      elb_status_code,
      target_status_code,
      user_agent,
    from
      aws_elb_access_log
    where
      type = 'https'
      and (ssl_cipher= '-' or ssl_protocol = '-')
    order by
      timestamp desc
  EOQ
}
