## Overview

Detect when an Amazon Elastic Block Store (EBS) snapshot was created without encryption. Unencrypted snapshots store sensitive data in plaintext, increasing the risk of unauthorized access and security vulnerabilities. Enforcing encryption ensures data protection, supports compliance, and safeguards sensitive information in cloud environments.

**References**:
- [Encrypting EBS Snapshots](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
- [Amazon EBS Best Practices](https://docs.aws.amazon.com/prescriptive-guidance/latest/encryption-best-practices/ec2-ebs.html)
- [AWS CLI Command: create-volume](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-volume.html)
