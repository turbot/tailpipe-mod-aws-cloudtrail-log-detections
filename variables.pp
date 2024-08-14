// Benchmarks and controls for specific services should override the "service" tag
locals {
  aws_common_tags = {
    category = "Security"
    plugin   = "aws"
    service  = "AWS"
  }
}
