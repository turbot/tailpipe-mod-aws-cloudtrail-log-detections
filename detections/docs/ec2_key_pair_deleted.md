## Overview

Detect when an EC2 key pair was deleted. Deleting a key pair may disrupt access to instances configured to use the key, potentially leading to operational issues or unauthorized access attempts. Monitoring these actions ensures that key deletions are authorized and do not compromise the availability or security of your instances.

**References**:
- [Managing Key Pairs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html)
- [AWS CLI Command: delete-key-pair](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-key-pair.html)
