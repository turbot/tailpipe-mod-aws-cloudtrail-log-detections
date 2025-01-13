## Description

This detection identifies instances where a restore image task is initiated for an Amazon Machine Image (AMI) from external accounts. Restoring AMIs from external sources can introduce untrusted or compromised images into your environment. Monitoring such activities is essential to prevent the deployment of potentially malicious or misconfigured resources.

## Risks

Restoring AMIs from external accounts poses a security threat as the source of the image might not be verified or trusted. Such images could contain malicious software, backdoors, or insecure configurations that compromise the security of your EC2 instances. This may lead to unauthorized access, data breaches, or exploitation of vulnerabilities within the imported image.

Unverified images may also fail to meet organizational compliance or security standards, leading to operational risks and non-compliance with regulatory frameworks or industry best practices. The presence of untrusted resources in your infrastructure increases the attack surface and could result in significant damage if exploited by malicious actors.

## References

- [AWS Documentation: VM Import/Export](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html)
- [AWS CLI Command: import-image](https://docs.aws.amazon.com/cli/latest/reference/ec2/import-image.html)
- [AWS Documentation: Restoring Amazon Machine Images (AMIs)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
