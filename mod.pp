mod "aws_cloudtrail_log_detections" {
  # hub metadata
  title         = "AWS CloudTrail Log Detections"
  description   = "Search your AWS CloudTrail logs for high risk actions using Tailpipe."
  color         = "#FF9900"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/aws-detections.svg"
  categories    = ["aws", "dashboard", "detections", "public cloud"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for AWS CloudTrail Log Detections"
    description = "Search your AWS CloudTrail logs for high risk actions using Tailpipe."
    #image       = "/images/mods/turbot/aws-social-graphic.png"
  }

}
