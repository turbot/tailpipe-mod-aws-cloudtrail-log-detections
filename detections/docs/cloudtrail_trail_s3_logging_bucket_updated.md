<!-- Restricting to CLI-based events, as console requests show all fields while CLI only shows updated fields. -->

## Overview

Detect when the S3 logging bucket associated with an AWS CloudTrail trail was updated. Changes to the logging bucket configuration can disrupt log delivery, expose sensitive log data, or create gaps in security monitoring. Monitoring these updates ensures the integrity, availability, and security of CloudTrail logs.

**References**:
- [Configuring Amazon S3 Buckets for CloudTrail](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html)
- [AWS CLI Command: update-trail](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/update-trail.html)