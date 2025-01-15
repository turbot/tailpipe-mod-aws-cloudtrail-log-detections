## Overview

Detect Amazon SNS topics that do not have encryption at rest enabled. Topics without encryption store messages in plaintext, increasing the risk of unauthorized access to sensitive data. Enabling encryption ensures secure message storage and aligns with data protection best practices.

**References**:
- [Amazon SNS Encryption at Rest](https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html)
- [AWS CLI Command: create-topic](https://docs.aws.amazon.com/cli/latest/reference/sns/create-topic.html)
- [AWS CLI Command: set-topic-attributes](https://docs.aws.amazon.com/cli/latest/reference/sns/set-topic-attributes.html)
