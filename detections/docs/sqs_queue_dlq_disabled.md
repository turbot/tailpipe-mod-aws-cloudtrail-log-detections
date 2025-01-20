## Overview

Detect Amazon SQS queues that do not have a Dead Letter Queue (DLQ) configured. DLQs provide a mechanism to capture messages that cannot be processed successfully, preventing data loss and enabling troubleshooting. Ensuring DLQs are enabled improves reliability and operational resilience.

**References**:
- [Amazon SQS Dead Letter Queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)
- [AWS CLI Command: create-queue](https://docs.aws.amazon.com/cli/latest/reference/sqs/create-queue.html)
- [AWS CLI Command: set-queue-attributes](https://docs.aws.amazon.com/cli/latest/reference/sqs/set-queue-attributes.html)
