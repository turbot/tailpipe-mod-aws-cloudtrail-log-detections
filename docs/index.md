# AWS CloudTrail Log Detections Mod

View dashboards, run reports, and scan for anomalies across your AWS CloudTrail logs.

## Documentation

- **[Dashboards →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-cloudtrail-log-detections/dashboards)**
- **[Benchmarks and detections →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-cloudtrail-log-detections/benchmarks)**

## Getting Started

### Installation

Install Powerpipe (https://powerpipe.io/downloads), or use Brew:

```sh
brew install turbot/tap/powerpipe
```

Install the mod:

```sh
mkdir dashboards
cd dashboards
powerpipe mod install github.com/turbot/tailpipe-mod-aws-cloudtrail-log-detections
```

This mod also requires [Tailpipe](https://tailpipe.io) with the [AWS plugin](https://hub.tailpipe.io/plugins/turbot/aws).

Install Tailpipe (https://tailpipe.io/downloads), or use Brew:

```sh
brew install turbot/tap/tailpipe
tailpipe plugin install aws
```

### Configuration

Configure your log source:

```sh
vi ~/.tailpipe/config/aws.tpc
```

```hcl
connection "aws" "aws_profile" {
  profile = "my-profile"
}

partition "aws_cloudtrail_log" "my_logs" {
  source "aws_s3_bucket" {
    connection = connection.aws.aws_profile
    bucket     = "aws-cloudtrail-logs-bucket"
  }
}
```

For AWS credentails, you can also use the [default AWS connection](https://tailpipe.io/docs/reference/config-files/connection/aws#default-connection), which uses the same the same mechanism as the AWS CLI (AWS environment variables, default profile, etc) or a connection with an access key pair. For more information on AWS connections in Tailpipe, please see [Managing AWS Connections](https://tailpipe.io/docs/reference/config-files/connection/aws).

You can also try this mod with locally downloaded files, like the [public dataset from flaws.cloud](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/):

```hcl
partition "aws_cloudtrail_log" "local_logs" {
  source "file"  {
    paths       = ["/Users/mscott/cloudtrail_logs"]
    file_layout = "%{DATA}.json.gz"
  }
}
```

For more examples on how you can configure your partitions, please see [aws_cloudtrail_log](https://hub.tailpipe.io/plugins/turbot/aws/tables/aws_cloudtrail_log).

### Log Collection

Collect logs:

```sh
tailpipe collect aws_cloudtrail_log
```

When running `tailpipe collect` for the first time, logs from the last 7 days are collected. Subsequent `tailpipe collect` runs will collect logs from the last collection date.

You can override the default behaviour by specifying `--from`:

```sh
tailpipe collect aws_cloudtrail_log --from 2025-01-01
```

You can also use relative times. For instance, to collect logs from the last 60 days:

```sh
tailpipe collect aws_cloudtrail_log --from T-60d
```

Please note that if you specify a date in `--from`, Tailpipe will delete any collected data for that partition starting from that date to help avoid gaps in the data.

For additional examples on using `tailpipe collect`, please see [tailpipe collect](https://tailpipe.io/docs/reference/cli/collect) reference documentation.

### Browsing Dashboards

Start the dashboard server:

```sh
powerpipe server
```

Browse and view your dashboards at **http://localhost:9033**.

### Running Benchmarks in Your Terminal

Instead of running benchmarks in a dashboard, you can also run them within your
terminal with the `powerpipe benchmark` command:

List available benchmarks:

```sh
powerpipe benchmark list
```

Run a benchmark:

```sh
powerpipe benchmark run aws_cloudtrail_log_detections.benchmark.mitre_attack_v161
```

Different output formats are also available, for more information please see
[Output Formats](https://powerpipe.io/docs/reference/cli/benchmark#output-formats).

## Open Source & Contributing

This repository is published under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0). Please see our [code of conduct](https://github.com/turbot/.github/blob/main/CODE_OF_CONDUCT.md). We look forward to collaborating with you!

[Steampipe](https://steampipe.io) and [Powerpipe](https://powerpipe.io) are products produced from this open source software, exclusively by [Turbot HQ, Inc](https://turbot.com). They are distributed under our commercial terms. Others are allowed to make their own distribution of the software, but cannot use any of the Turbot trademarks, cloud services, etc. You can learn more in our [Open Source FAQ](https://turbot.com/open-source).

## Get Involved

**[Join #powerpipe on Slack →](https://turbot.com/community/join)**

Want to help but don't know where to start? Pick up one of the `help wanted` issues:

- [Powerpipe](https://github.com/turbot/powerpipe/labels/help%20wanted)
- [AWS Compliance Mod](https://github.com/turbot/steampipe-mod-aws-compliance/labels/help%20wanted)
