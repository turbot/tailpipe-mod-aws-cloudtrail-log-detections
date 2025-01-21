## Overview

Detect when an Amazon SQS queue was created without encryption at rest enabled. SQS queues without encryption store data in plaintext, increasing the risk of unauthorized access and compromising sensitive messages. Enabling encryption ensures secure message storage and aligns with best practices for data protection.

**References**:
- [Encryption at Rest for Amazon SQS](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html)
- [AWS CLI Command: create-queue](https://docs.aws.amazon.com/cli/latest/reference/sqs/create-queue.html)
- [AWS CLI Command: set-queue-attributes](https://docs.aws.amazon.com/cli/latest/reference/sqs/set-queue-attributes.html)
