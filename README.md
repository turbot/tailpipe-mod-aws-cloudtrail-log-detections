# AWS Detections Mod for Powerpipe

Scan AWS logs for high risk activity.

Run checks in a dashboard:
![image](https://raw.githubusercontent.com/turbot/tailpipe-mod-aws-detections/main/docs/aws_cis_v400_dashboard.png)

Or in a terminal:
![image](https://raw.githubusercontent.com/turbot/tailpipe-mod-aws-detections/main/docs/aws_cis_v400_console.png)

## Documentation

- **[Benchmarks and detections →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-detections/benchmarks)**
- **[Named queries →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-detections/queries)**

## Getting Started

### Installation

Install Powerpipe (https://powerpipe.io/downloads), or use Brew:

```sh
brew install turbot/tap/powerpipe
```

This mod also requires [Tailpipe](https://tailpipe.io) with the [AWS plugin](https://hub.tailpipe.io/plugins/turbot/aws) as the data source. Install Tailpipe (https://tailpipe.io/downloads), or use Brew:

```sh
brew install turbot/tap/tailpipe
tailpipe plugin install aws
```

Tailpipe will automatically use your default AWS credentials. Optionally, you can [setup multiple accounts](https://hub.tailpipe.io/plugins/turbot/aws#multi-account-connections) or [customize AWS credentials](https://hub.tailpipe.io/plugins/turbot/aws#configuring-aws-credentials).

Collect logs from an S3 bucket:

```terraform
partition "aws_cloudtrail_log" "dev" {
  source "aws_s3_bucket" {
    bucket = "aws-cloudtrail-logs-bucket"
  }
}
```

Or from the CloudTrail API:

```terraform
partition "aws_cloudtrail_log" "dev" {
  source "aws_cloudtrail_api" {
    region = "us-east-2"
  }
}
```

```shell
tailpipe collect aws_cloudtrail_log.dev
```

Finally, install the mod:

```sh
mkdir dashboards
cd dashboards
powerpipe mod init
powerpipe mod install github.com/turbot/tailpipe-mod-aws-detections
```

### Browsing Dashboards

Start Tailpipe as the data source:

```sh
tailpipe service start
```

Start the dashboard server:

```sh
powerpipe server
```

Browse and view your dashboards at **http://localhost:9033**.

### Running Checks in Your Terminal

Instead of running benchmarks in a dashboard, you can also run them within your
terminal with the `powerpipe benchmark` command:

List available benchmarks:

```sh
powerpipe benchmark list
```

Run a benchmark:

```sh
powerpipe benchmark run aws_detections.benchmark.cloudtrail_log_detections
```

Different output formats are also available, for more information please see
[Output Formats](https://powerpipe.io/docs/reference/cli/benchmark#output-formats).

## Open Source & Contributing

This repository is published under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0). Please see our [code of conduct](https://github.com/turbot/.github/blob/main/CODE_OF_CONDUCT.md). We look forward to collaborating with you!

[Tailpipe](https://tailpipe.io) and [Powerpipe](https://powerpipe.io) are products produced from this open source software, exclusively by [Turbot HQ, Inc](https://turbot.com). They are distributed under our commercial terms. Others are allowed to make their own distribution of the software, but cannot use any of the Turbot trademarks, cloud services, etc. You can learn more in our [Open Source FAQ](https://turbot.com/open-source).

## Get Involved

**[Join #powerpipe on Slack →](https://turbot.com/community/join)**

Want to help but don't know where to start? Pick up one of the `help wanted` issues:

- [Powerpipe](https://github.com/turbot/powerpipe/labels/help%20wanted)
- [AWS Detections Mod](https://github.com/turbot/tailpipe-mod-aws-detections/labels/help%20wanted)
