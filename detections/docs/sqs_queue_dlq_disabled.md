## Overview

Detect when an Amazon SQS queue was created without a Dead Letter Queue (DLQ) configured. DLQs capture messages that cannot be processed successfully, preventing data loss and enabling troubleshooting. Ensuring DLQs are enabled improves reliability and operational resilience.

**References**:
- [Amazon SQS Dead Letter Queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)
- [AWS CLI Command: create-queue](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sqs/create-queue.html)
- [AWS CLI Command: set-queue-attributes](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sqs/set-queue-attributes.html)
