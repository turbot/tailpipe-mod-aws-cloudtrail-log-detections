## Overview

Detect when an Amazon SNS topic was granted public access. Publicly accessible SNS topics expose sensitive messaging workflows to unauthorized access, increasing the risk of message interception, data breaches, and resource abuse. Restricting access to trusted entities ensures secure messaging and aligns with best practices.

**References**:
- [Amazon SNS Access Control](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html)
- [AWS CLI Command: set-topic-attributes](https://docs.aws.amazon.com/cli/latest/reference/sns/set-topic-attributes.html)
- [AWS CLI Command: get-topic-attributes](https://docs.aws.amazon.com/cli/latest/reference/sns/get-topic-attributes.html)
