mod "aws_cloudtrail_log_detections" {
  # hub metadata
  title         = "AWS CloudTrail Log Detections"
  description   = "Run detections and view dashboards for your AWS CloudTrail logs to monitor and analyze activity across your AWS accounts using Powerpipe and Tailpipe."
  color         = "#FF9900"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/aws-cloudtrail-log-detections.svg"
  categories    = ["aws", "dashboard", "detections", "public cloud"]
  database      = var.database

  opengraph {
    title       = "Powerpipe Mod for AWS CloudTrail Log Detections"
    description = "Run detections and view dashboards for your AWS CloudTrail logs to monitor and analyze activity across your AWS accounts using Powerpipe and Tailpipe."
    image       = "/images/mods/turbot/aws-cloudtrail-log-detections-social-graphic.png"
  }

}
