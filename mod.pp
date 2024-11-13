mod "aws_detections" {
  # hub metadata
  title         = "AWS Detections"
  description   = "Search your AWS logs for high risk actions using Tailpipe."
  color         = "#FF9900"
  #documentation = file("./docs/index.md")
  #icon          = "/images/mods/turbot/aws.svg"
  categories    = ["aws", "security"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for AWS Detections"
    description = "Search your AWS logs for high risk actions using Tailpipe."
    #image       = "/images/mods/turbot/aws-social-graphic.png"
  }

}
