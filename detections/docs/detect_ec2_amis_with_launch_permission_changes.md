## Description

This detection identifies changes to the launch permissions of Amazon Machine Images (AMIs) in your AWS environment. Launch permissions determine which AWS accounts are allowed to launch instances from an AMI. Changes to these permissions, especially when AMIs are shared with external accounts, may indicate unauthorized access or misconfigurations.

## Risks

Modifying the launch permissions of AMIs can pose security and operational risks. Granting unauthorized access to an AMI may expose sensitive configurations or proprietary software included in the image. This could lead to unauthorized replication, misuse, or deployment of your AMIs in untrusted environments.

Additionally, unintentional changes to launch permissions could disrupt workflows or violate compliance requirements, particularly if sensitive or regulated AMIs are shared with external entities. Ensuring proper monitoring and control over AMI permissions is critical for maintaining a secure and compliant AWS environment.

## References

- [AWS Documentation: Sharing AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html)
- [AWS CLI Command: modify-image-attribute](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-image-attribute.html)
